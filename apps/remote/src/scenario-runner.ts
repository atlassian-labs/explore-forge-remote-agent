import {
  type Artifact,
  type Message,
  Role,
  TaskState,
  type TaskStatus,
} from "@a2a-js/sdk";
import { AgentEvent, type AgentExecutor } from "@a2a-js/sdk/server";
import {
  createRemoteA2aCompletedRecord,
  emitRemoteLogRecord,
  type RemoteLogRecordLogger,
} from "@forge-ahead/remote/logging";
import type { FakeOAuth } from "./fake-oauth.js";
import {
  projectScenarioSteps,
  type ScenarioTransport,
} from "./scenario-presentation.js";
import {
  invocationContextFromParts,
  type LoadedScenario,
  type ScenarioStep,
  selectScenarioWithDiagnostic,
} from "./scenarios.js";

export type DiagnosticEvent = Record<string, unknown>;
export type Diagnostics = (event: DiagnosticEvent) => void;
export type Delay = (milliseconds: number) => Promise<void>;

type JiraCallbackCredentials = {
  apiBaseUrl: string;
  invokerId: string;
  tenantId: string;
  userToken: string;
};

type StepResult =
  | { kind: "continue" }
  | { kind: "paused" }
  | { kind: "terminal"; state: TaskState };

type ScenarioSession = {
  canceled: boolean;
  contextId: string;
  invokerId: string;
  nextStep: number;
  scenario: LoadedScenario;
  sessionId: string;
  transport: ScenarioTransport;
  status?: TaskStatus;
  taskId: string;
  tenantId: string;
  // True while an `auth-check` step is waiting for the user to authorize.
  waitingForAuthorization?: boolean;
};

export type ScenarioRunnerOptions = {
  delay?: Delay;
  diagnostics?: Diagnostics;
  enableRealJiraCallbacks?: boolean;
  logRequestData?: boolean;
  jiraFetch?: typeof fetch;
  oauth?: Pick<FakeOAuth, "authorizeUrl" | "isAuthorized">;
  remoteLogger?: RemoteLogRecordLogger;
  scenarios: LoadedScenario[];
  loadSteps?: (id: string) => ScenarioStep[];
  transport?: () => ScenarioTransport;
};

const taskStates: Record<string, TaskState> = {
  working: TaskState.TASK_STATE_WORKING,
  completed: TaskState.TASK_STATE_COMPLETED,
  rejected: TaskState.TASK_STATE_REJECTED,
  failed: TaskState.TASK_STATE_FAILED,
  canceled: TaskState.TASK_STATE_CANCELED,
  "input-required": TaskState.TASK_STATE_INPUT_REQUIRED,
  "auth-required": TaskState.TASK_STATE_AUTH_REQUIRED,
  unknown: TaskState.TASK_STATE_UNSPECIFIED,
};

function agentMessage(
  taskId: string,
  contextId: string,
  text?: string,
): Message {
  return {
    role: Role.ROLE_AGENT,
    parts: text
      ? [
          {
            content: { $case: "text", value: text },
            filename: "",
            mediaType: "text/markdown",
            metadata: {},
          },
        ]
      : [],
    messageId: crypto.randomUUID(),
    taskId,
    contextId,
    metadata: {},
    extensions: [],
    referenceTaskIds: [],
  };
}

function artifact(
  step: NonNullable<LoadedScenario["steps"][number]["artifact"]>,
): Artifact {
  return {
    artifactId: step.artifactId,
    name: step.name ?? "",
    description: step.description ?? "",
    parts: step.parts.map((part) => ({
      content: { $case: "text", value: part.text ?? "" },
      filename: "",
      mediaType: "text/markdown",
      metadata: {},
    })),
    metadata: step.metadata ?? {},
    extensions: [],
  };
}

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object"
    ? (value as Record<string, unknown>)
    : {};
}

const secretKey = /token|secret|authorization|password|credential/i;

// Deep copy with credential-looking keys replaced, so request data can be
// logged without leaking tokens that happen to appear in a payload.
export function redactSecrets(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSecrets);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        key,
        secretKey.test(key) ? "[redacted]" : redactSecrets(entry),
      ]),
    );
  return value;
}

// The A2A message parts Jira sent: the text part (instructions, optional
// space instructions and related-resource titles) and the data part
// (userAccountId, agentAccountId, invocationType, issue, comment, automation).
function requestDataFromParts(parts: unknown[]): {
  texts: string[];
  data: unknown[];
} {
  const texts: string[] = [];
  const data: unknown[] = [];
  for (const part of parts) {
    const value = record(part);
    const content = record(value.content);
    const textValue =
      value.text ?? (content.$case === "text" ? content.value : undefined);
    if (typeof textValue === "string") texts.push(textValue);
    const dataValue =
      value.data ?? (content.$case === "data" ? content.value : undefined);
    if (dataValue !== undefined) data.push(redactSecrets(dataValue));
  }
  return { texts, data };
}

function text(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

type RequestContextForCredentials = {
  context: { tenant?: string | undefined; user?: unknown };
};

function jiraCredentialParts(
  requestContext: RequestContextForCredentials,
): Partial<JiraCallbackCredentials> {
  const remoteContext = record(
    record(requestContext.context.user).forgeRemoteContext,
  );
  const fit = record(remoteContext.fit);
  const app = record(fit.app);
  return {
    apiBaseUrl: text(app.apiBaseUrl ?? app.apiBaseURL),
    // Jira's FIT names the invoker `principal` (an account id); `sub` is absent.
    invokerId: text(fit.sub) ?? text(fit.principal),
    // `context.tenant` is empty because the library only accepts an ARI there;
    // Jira sends a bare cloud id, so read it from the FIT directly.
    tenantId:
      text(requestContext.context.tenant) ?? text(record(fit.context).cloudId),
    userToken: text(record(record(remoteContext.forwardedTokens).user).token),
  } as Partial<JiraCallbackCredentials>;
}

function jiraCallbackCredentials(
  requestContext: RequestContextForCredentials,
): JiraCallbackCredentials | undefined {
  const { apiBaseUrl, invokerId, tenantId, userToken } =
    jiraCredentialParts(requestContext);
  return apiBaseUrl && userToken && invokerId && tenantId
    ? { apiBaseUrl, userToken, invokerId, tenantId }
    : undefined;
}

// Names (never values) of the credential parts a real Jira callback needs
// that this request did not carry.
function missingJiraCredentials(
  requestContext: RequestContextForCredentials,
): string[] {
  const parts = jiraCredentialParts(requestContext);
  return (
    [
      ["apiBaseUrl", "fit.app.apiBaseUrl"],
      ["invokerId", "fit.principal"],
      ["tenantId", "tenant (fit.context.cloudId)"],
      ["userToken", "x-forge-oauth-user header"],
    ] as const
  )
    .filter(([key]) => !parts[key])
    .map(([, source]) => source);
}

// The shape of the verified FIT: claim names only, plus the API base URL
// (a URL, not a credential), to see what Jira actually sends.
function fitShape(requestContext: RequestContextForCredentials): {
  apiBaseUrl: string | undefined;
  fitAppKeys: string[];
  fitContextKeys: string[];
  fitKeys: string[];
} {
  const fit = record(
    record(record(requestContext.context.user).forgeRemoteContext).fit,
  );
  const app = record(fit.app);
  return {
    apiBaseUrl: text(app.apiBaseUrl ?? app.apiBaseURL),
    fitAppKeys: Object.keys(app),
    fitContextKeys: Object.keys(record(fit.context)),
    fitKeys: Object.keys(fit),
  };
}

type JiraCallbackOutcome = {
  body?: unknown;
  httpStatus?: number;
  result: "completed" | "auth-required" | "rejected" | "failed";
};

// Fields requested by a `read` step: enough to show what was read without
// pulling the full issue (the description is a large Atlassian Document).
const readFields = "summary,status,labels";

// Jira's reply as JSON when it is JSON, otherwise a bounded text excerpt.
async function responseBody(response: Response): Promise<unknown> {
  try {
    const text = await response.text();
    try {
      return JSON.parse(text);
    } catch {
      return text.slice(0, 500);
    }
  } catch {
    return undefined;
  }
}

// One line for the task status, from a `read` response: key, summary, status.
function describeIssue(body: unknown): string | undefined {
  const issue = record(body);
  const fields = record(issue.fields);
  const key = text(issue.key);
  const summary = text(fields.summary);
  const status = text(record(fields.status).name);
  if (!key && !summary) return undefined;
  return `Read Jira work item ${[key, summary].filter(Boolean).join(": ")}${
    status ? ` (status: ${status})` : ""
  }.`;
}

async function runJiraCallback(
  step: LoadedScenario["steps"][number],
  workItemId: string,
  credentials: JiraCallbackCredentials,
  jiraFetch: typeof fetch,
  accepted: boolean,
): Promise<JiraCallbackOutcome> {
  const issuePath = `/rest/api/3/issue/${encodeURIComponent(workItemId)}`;
  // Keep any path on the base (for example an API gateway's /ex/jira/{cloudId})
  // instead of letting an absolute path replace it.
  const baseUrl = credentials.apiBaseUrl.replace(/\/+$/, "");
  const request = (path: string, init?: RequestInit) =>
    jiraFetch(new URL(`${baseUrl}${issuePath}${path}`).toString(), {
      ...init,
      headers: {
        Authorization: `Bearer ${credentials.userToken}`,
        ...(init?.body ? { "content-type": "application/json" } : {}),
      },
    });
  const response =
    step.action === "read"
      ? await request(`?fields=${readFields}`, { method: "GET" })
      : step.action === "comment"
        ? await request("/comment", {
            method: "POST",
            body: JSON.stringify({
              body: {
                type: "doc",
                version: 1,
                content: [
                  {
                    type: "paragraph",
                    content: [
                      { type: "mention", attrs: { id: credentials.invokerId } },
                      { type: "text", text: " Jira callback smoke test." },
                    ],
                  },
                ],
              },
            }),
          })
        : step.action === "transition" && step.transitionId
          ? await request("/transitions", {
              method: "POST",
              body: JSON.stringify({ transition: { id: step.transitionId } }),
            })
          : undefined;
  if (!response) return { result: "rejected" };
  const outcome = {
    httpStatus: response.status,
    body: await responseBody(response),
  };
  if (response.status === 401 || response.status === 403)
    return { ...outcome, result: "auth-required" };
  return {
    ...outcome,
    result: response.ok ? "completed" : accepted ? "failed" : "rejected",
  };
}

function terminal(
  logger: RemoteLogRecordLogger | undefined,
  taskId: string,
  contextId: string,
  state: TaskState,
): void {
  if (logger)
    emitRemoteLogRecord(
      logger,
      createRemoteA2aCompletedRecord({
        taskId,
        contextId,
        state: TaskState[state],
      }),
    );
}

export function createScenarioRunner({
  scenarios,
  diagnostics = () => {},
  delay = async () => {},
  enableRealJiraCallbacks = false,
  // On by default; set LOG_AGENT_REQUEST_DATA=false to stop logging request content.
  logRequestData = process.env.LOG_AGENT_REQUEST_DATA !== "false",
  jiraFetch = fetch,
  oauth,
  remoteLogger,
  loadSteps,
  transport = () => "polling",
}: ScenarioRunnerOptions): AgentExecutor {
  const sessions = new Map<string, ScenarioSession>();
  // What the agent sends back to Jira: status messages, artifacts, cancels.
  const logResponse = (event: string, fields: Record<string, unknown>) => {
    if (logRequestData) diagnostics({ event, ...fields });
  };
  const messageText = (message: Message | undefined): string =>
    (message?.parts ?? [])
      .map((part) => {
        const content = record(record(part).content);
        return content.$case === "text" ? String(content.value) : "";
      })
      .join("");
  const publishStatus = (
    eventBus: { publish(event: unknown): void },
    taskId: string,
    contextId: string,
    task: unknown,
    index: number,
    status: TaskStatus,
  ) => {
    if (index === 0)
      eventBus.publish(
        AgentEvent.task(
          task
            ? ({ ...(task as object), status } as never)
            : {
                id: taskId,
                contextId,
                artifacts: [],
                history: [],
                metadata: {},
                status,
              },
        ),
      );
    else
      eventBus.publish(
        AgentEvent.statusUpdate({ taskId, contextId, status, metadata: {} }),
      );
  };
  const playStep = async ({
    contextId,
    eventBus,
    index,
    invocationContext,
    session,
    step,
    task,
    trustedCredentials,
  }: {
    contextId: string;
    eventBus: { publish(event: unknown): void };
    index: number;
    invocationContext: ReturnType<typeof invocationContextFromParts>;
    session: ScenarioSession;
    step: LoadedScenario["steps"][number];
    task: unknown;
    trustedCredentials: JiraCallbackCredentials | undefined;
  }): Promise<StepResult> => {
    if (step.event === "artifact-update" && step.artifact) {
      eventBus.publish(
        AgentEvent.artifactUpdate({
          taskId: session.taskId,
          contextId,
          artifact: artifact(step.artifact),
          append: step.append === true,
          lastChunk: step.lastChunk === true,
          metadata: {},
        }),
      );
      logResponse("agent-artifact", {
        taskId: session.taskId,
        contextId,
        step: index,
        artifactId: step.artifact.artifactId,
        name: step.artifact.name,
        description: step.artifact.description,
        append: step.append === true,
        lastChunk: step.lastChunk === true,
        parts: step.artifact.parts.map((part) => part.text ?? ""),
      });
      return { kind: "continue" };
    }
    if (step.event === "jira-callback" && step.action) {
      const credentials =
        enableRealJiraCallbacks && step.real === true && trustedCredentials;
      // A simulated callback only needs the work item. A real one also needs
      // the validated tenant and invoker it will act as.
      const unavailable =
        invocationContext.workItem.availability !== "available" ||
        (credentials !== false &&
          credentials !== undefined &&
          (!session.tenantId || !session.invokerId));
      const realCall = !unavailable && Boolean(credentials);
      const outcome: Omit<JiraCallbackOutcome, "result"> & {
        result: string;
      } = unavailable
        ? { result: "context-unavailable" }
        : credentials
          ? await runJiraCallback(
              step,
              invocationContext.workItem.id ?? "",
              credentials,
              jiraFetch,
              session.status?.state === TaskState.TASK_STATE_WORKING,
            ).catch(
              (): JiraCallbackOutcome => ({
                result:
                  session.status?.state === TaskState.TASK_STATE_WORKING
                    ? "failed"
                    : "rejected",
              }),
            )
          : { result: step.result ?? "simulated" };
      const result = outcome.result;
      const state =
        result === "auth-required"
          ? TaskState.TASK_STATE_AUTH_REQUIRED
          : result === "rejected"
            ? TaskState.TASK_STATE_REJECTED
            : result === "failed"
              ? TaskState.TASK_STATE_FAILED
              : (session.status?.state ?? TaskState.TASK_STATE_WORKING);
      const status = {
        state,
        message: agentMessage(
          session.taskId,
          contextId,
          step.message ??
            (result === "context-unavailable"
              ? "Simulated Jira callback skipped because the active invocation context is unavailable; no Jira action was performed."
              : realCall
                ? ((step.action === "read" && result === "completed"
                    ? describeIssue(outcome.body)
                    : undefined) ?? `Jira ${step.action} callback (${result}).`)
                : `Simulated Jira ${step.action} callback (${result}); no Jira action was performed.`),
        ),
        timestamp: new Date().toISOString(),
      };
      session.status = status;
      logResponse("agent-status", {
        taskId: session.taskId,
        contextId,
        step: index,
        source: "jira-callback",
        state: TaskState[state],
        message: messageText(status.message),
      });
      diagnostics({
        event: "jira-callback",
        taskId: session.taskId,
        contextId: session.contextId,
        sessionId: session.sessionId,
        tenantId: session.tenantId,
        invokerId: session.invokerId,
        ...(invocationContext.workItem.id
          ? { workItemId: invocationContext.workItem.id }
          : {}),
        scenarioId: session.scenario.id,
        action: step.action,
        result,
        ...(outcome.httpStatus === undefined
          ? {}
          : { httpStatus: outcome.httpStatus }),
        // Why no real call was made, so "simulated" is never a mystery.
        ...(realCall || result === "context-unavailable"
          ? {}
          : {
              simulatedBecause: [
                ...(enableRealJiraCallbacks ? [] : ["env-flag-off"]),
                ...(step.real === true ? [] : ["step-not-real"]),
                ...(trustedCredentials
                  ? []
                  : ["no-forge-user-token-or-tenant"]),
              ],
            }),
      });
      // What Jira answered, for real calls only (simulated ones have none).
      if (realCall && outcome.httpStatus !== undefined)
        logResponse("jira-response", {
          taskId: session.taskId,
          contextId,
          step: index,
          action: step.action,
          httpStatus: outcome.httpStatus,
          body: redactSecrets(outcome.body),
        });
      publishStatus(eventBus, session.taskId, contextId, task, index, status);
      if (result === "auth-required") return { kind: "paused" };
      if (result === "rejected" || result === "failed")
        return { kind: "terminal", state };
      return { kind: "continue" };
    }
    // `{{authorizeUrl}}` in a message becomes this task's fake-OAuth link.
    const fill = (text: string | undefined) =>
      text?.replaceAll(
        "{{authorizeUrl}}",
        oauth?.authorizeUrl(session.taskId) ?? "(fake OAuth is not enabled)",
      );
    if (step.event === "auth-check") {
      // Wait for the user to approve on the fake consent page, then continue
      // on the same task: no reply needed. The task stays auth-required while
      // waiting, and the SDK keeps the stream open for that state.
      const pollMs = 1000;
      // Under Jira's ~125 s cutoff for an open request (cloudflared logs
      // "stream canceled by remote" at exactly that point). Still bounded, so
      // an abandoned task cannot poll forever.
      const timeoutMs = step.timeoutMs ?? 90 * 1000;
      let waitedMs = 0;
      session.waitingForAuthorization = true;
      try {
        while (
          oauth?.isAuthorized(session.taskId) !== true &&
          waitedMs < timeoutMs &&
          !session.canceled
        ) {
          await delay(pollMs);
          waitedMs += pollMs;
        }
      } finally {
        session.waitingForAuthorization = false;
      }
      if (session.canceled) return { kind: "paused" };
      const authorized = oauth?.isAuthorized(session.taskId) === true;
      diagnostics({
        event: "oauth-check",
        taskId: session.taskId,
        contextId: session.contextId,
        scenarioId: session.scenario.id,
        authorized,
        waitedMs,
      });
      if (authorized) return { kind: "continue" };
      const status = {
        state: TaskState.TASK_STATE_FAILED,
        message: agentMessage(
          session.taskId,
          contextId,
          fill(step.message) ?? "Authorization was not granted in time.",
        ),
        timestamp: new Date().toISOString(),
      };
      session.status = status;
      logResponse("agent-status", {
        taskId: session.taskId,
        contextId,
        step: index,
        source: "auth-check",
        state: "TASK_STATE_FAILED",
        message: fill(step.message) ?? "",
      });
      publishStatus(eventBus, session.taskId, contextId, task, index, status);
      return { kind: "terminal", state: TaskState.TASK_STATE_FAILED };
    }
    if (step.event !== "status-update") {
      diagnostics({
        event: "compliance-warning",
        taskId: session.taskId,
        contextId: session.contextId,
        sessionId: session.sessionId,
        tenantId: session.tenantId,
        scenarioId: session.scenario.id,
        warning: "unsupported-scenario-event",
      });
      return { kind: "continue" };
    }
    const state = step.state ? taskStates[step.state] : session.status?.state;
    if (!state) {
      diagnostics({
        event: "compliance-warning",
        taskId: session.taskId,
        contextId: session.contextId,
        sessionId: session.sessionId,
        tenantId: session.tenantId,
        scenarioId: session.scenario.id,
        warning: "unsupported-task-state",
      });
      return { kind: "continue" };
    }
    const status = {
      state,
      message: agentMessage(session.taskId, contextId, fill(step.message)),
      timestamp: new Date().toISOString(),
    };
    session.status = status;
    logResponse("agent-status", {
      taskId: session.taskId,
      contextId,
      step: index,
      source: "status-update",
      state: TaskState[state],
      waitForUserInput: step.waitForUserInput === true,
      message: fill(step.message) ?? "",
    });
    diagnostics({
      event: "lifecycle",
      taskId: session.taskId,
      contextId: session.contextId,
      sessionId: session.sessionId,
      tenantId: session.tenantId,
      scenarioId: session.scenario.id,
      state: step.state ?? "unknown",
    });
    publishStatus(eventBus, session.taskId, contextId, task, index, status);
    // The SDK closes a stream only on a statusUpdate for a terminal or
    // input-required state, never on the initial Task event. A first-step
    // input pause is published as that Task, so without this the stream stays
    // open and the user's reply (which republishes a Task) is rejected with
    // "Stream ordering violation" on that stale stream.
    if (index === 0 && state === TaskState.TASK_STATE_INPUT_REQUIRED)
      eventBus.publish(
        AgentEvent.statusUpdate({
          taskId: session.taskId,
          contextId,
          status,
          metadata: {},
        }),
      );
    if (step.waitForUserInput) {
      diagnostics({
        event: "paused",
        taskId: session.taskId,
        contextId: session.contextId,
        sessionId: session.sessionId,
        tenantId: session.tenantId,
        scenarioId: session.scenario.id,
        state: step.state ?? "unknown",
      });
      return { kind: "paused" };
    }
    return [
      TaskState.TASK_STATE_COMPLETED,
      TaskState.TASK_STATE_REJECTED,
      TaskState.TASK_STATE_FAILED,
      TaskState.TASK_STATE_CANCELED,
    ].includes(state)
      ? { kind: "terminal", state }
      : { kind: "continue" };
  };

  return {
    async execute(requestContext, eventBus) {
      const { taskId, contextId, task, userMessage } = requestContext;
      const existing = sessions.get(taskId);
      const invocationContext = invocationContextFromParts(userMessage.parts);
      // Safe view of the request context: ids, availability, field names and
      // sizes only. Never message text, field values, comment bodies or tokens.
      diagnostics({
        event: "invocation-context",
        taskId,
        contextId,
        resumed: existing !== undefined,
        partKinds: userMessage.parts.map(
          (part) =>
            (part as { content?: { $case?: string } }).content?.$case ??
            "unknown",
        ),
        textLength: invocationContext.text.length,
        entrySurface: invocationContext.entrySurface,
        tenantId: invocationContext.tenantId,
        invokerId: invocationContext.invokerId,
        workItemId: invocationContext.workItem.id,
        workItemAvailability: invocationContext.workItem.availability,
        workItemFieldNames: Object.keys(invocationContext.workItem.fields),
        commentId: invocationContext.comment.id,
        commentAvailability: invocationContext.comment.availability,
        commentBodyLength: invocationContext.comment.body?.length,
      });
      if (logRequestData)
        diagnostics({
          event: "request-data",
          taskId,
          contextId,
          resumed: existing !== undefined,
          messageId: userMessage.messageId,
          ...requestDataFromParts(userMessage.parts),
        });
      const trustedCredentials = jiraCallbackCredentials(requestContext);
      diagnostics({
        event: "jira-credentials",
        taskId,
        contextId,
        available: trustedCredentials !== undefined,
        missing: missingJiraCredentials(requestContext),
        ...fitShape(requestContext),
      });
      // A message for a task that is still waiting for authorization (the
      // spec says agents SHOULD accept these) must not start a second run of
      // the later steps. Answer with the current status and the same link.
      if (existing?.waitingForAuthorization && existing.status) {
        diagnostics({
          event: "message-while-auth-required",
          taskId,
          contextId: existing.contextId,
          scenarioId: existing.scenario.id,
        });
        // Blocking requests can be answered with the current status. A second
        // stream cannot: the SDK shares one event bus per task, a new stream
        // must start with a Task or Message, and the stream that is already
        // open rejects exactly those. So publish nothing for streams and leave
        // the waiting task untouched.
        if (transport() !== "streaming")
          publishStatus(
            eventBus,
            existing.taskId,
            existing.contextId,
            task,
            existing.nextStep,
            existing.status,
          );
        return;
      }
      const selection = existing
        ? undefined
        : selectScenarioWithDiagnostic(scenarios, invocationContext);
      const selectedScenario = existing?.scenario ?? selection?.scenario;
      if (!selectedScenario) return;
      const requestedTransport = transport();
      const selectedTransport = existing?.transport ?? requestedTransport;
      const scenario = existing?.scenario ?? {
        ...selectedScenario,
        steps: projectScenarioSteps(
          loadSteps?.(selectedScenario.id) ?? selectedScenario.steps,
          selectedTransport,
        ),
      };
      const session = existing ?? {
        canceled: false,
        contextId,
        invokerId: trustedCredentials?.invokerId ?? invocationContext.invokerId,
        nextStep: 0,
        scenario,
        sessionId: crypto.randomUUID(),
        taskId,
        tenantId:
          trustedCredentials?.tenantId ??
          requestContext.context.tenant ??
          invocationContext.tenantId,
        transport: selectedTransport,
      };
      if (existing && selectedTransport !== requestedTransport)
        diagnostics({
          event: "scenario.transport.mismatch",
          requestedTransport,
          taskId,
          transport: selectedTransport,
        });
      sessions.set(taskId, session);
      if (existing && selectedTransport === "streaming" && session.status)
        eventBus.publish(
          AgentEvent.task(
            task
              ? ({ ...(task as object), status: session.status } as never)
              : {
                  id: session.taskId,
                  contextId: session.contextId,
                  artifacts: [],
                  history: [],
                  metadata: {},
                  status: session.status,
                },
          ),
        );
      diagnostics({
        event: "scenario-selected",
        taskId: session.taskId,
        contextId: session.contextId,
        sessionId: session.sessionId,
        tenantId: session.tenantId,
        invokerId: session.invokerId,
        scenarioId: scenario.id,
        selection: existing ? "resume" : (selection?.category ?? "default"),
        transport: session.transport,
        workItemAvailability: invocationContext.workItem.availability,
        commentAvailability: invocationContext.comment.availability,
        callbackReadiness: scenario.steps.some(
          (step) => step.event === "jira-callback",
        )
          ? enableRealJiraCallbacks
            ? "real-enabled"
            : "simulated"
          : "not-configured",
      });
      for (
        let index = session.nextStep;
        index < scenario.steps.length;
        index++
      ) {
        const step = scenario.steps[index];
        if (!step) return;
        if (step.delayMs) await delay(step.delayMs);
        if (session.canceled) return;
        session.nextStep = index + 1;
        const result = await playStep({
          contextId,
          eventBus,
          index,
          invocationContext,
          session,
          step,
          task,
          trustedCredentials,
        });
        if (result.kind === "continue") continue;
        if (result.kind === "paused") return;
        terminal(remoteLogger, taskId, contextId, result.state);
        sessions.delete(taskId);
        return;
      }
    },
    async cancelTask(taskId, eventBus) {
      const session = sessions.get(taskId);
      if (!session || session.canceled) return;
      session.canceled = true;
      diagnostics({
        event: "canceled",
        taskId: session.taskId,
        contextId: session.contextId,
        sessionId: session.sessionId,
        tenantId: session.tenantId,
        scenarioId: session.scenario.id,
      });
      terminal(
        remoteLogger,
        taskId,
        session.contextId,
        TaskState.TASK_STATE_CANCELED,
      );
      logResponse("agent-status", {
        taskId,
        contextId: session.contextId,
        source: "cancel",
        state: "TASK_STATE_CANCELED",
        message: "Task canceled.",
      });
      eventBus.publish(
        AgentEvent.statusUpdate({
          taskId,
          contextId: session.contextId,
          status: {
            state: TaskState.TASK_STATE_CANCELED,
            message: agentMessage(taskId, session.contextId, "Task canceled."),
            timestamp: new Date().toISOString(),
          },
          metadata: {},
        }),
      );
      sessions.delete(taskId);
    },
  };
}
