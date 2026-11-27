import type { AgentCard } from "@a2a-js/sdk";
import { DefaultRequestHandler, InMemoryTaskStore } from "@a2a-js/sdk/server";
import { jsonRpcHandler } from "@a2a-js/sdk/server/express";
import {
  ok,
  type ProblemDetails,
  type Result,
  StandardError,
} from "@forge-ahead/errors";
import { ATLASSIAN_FORGE_JWKS_URL } from "@forge-ahead/remote";
import type { ForgeRemoteRequest } from "@forge-ahead/remote/express";
import {
  forgeRemoteAuthMiddleware,
  forgeRemoteServerCallContextBuilder,
  forgeRemoteUserBuilder,
} from "@forge-ahead/remote/express";
import {
  createRemoteAuthAcceptedRecord,
  emitRemoteLogRecord,
  type RemoteLogRecordLogger,
} from "@forge-ahead/remote/logging";
import express, { type Express } from "express";
import { createFakeOAuth } from "./fake-oauth.js";
import { log, verbose } from "./logger.js";
import {
  currentTraceId,
  runWithTraceId,
  traceIdFromHeaders,
} from "./request-trace.js";
import {
  createScenarioRunner,
  type Delay,
  type DiagnosticEvent,
  type Diagnostics,
  redactSecrets,
} from "./scenario-runner.js";
import {
  currentScenarioTransport,
  runWithScenarioTransport,
  transportForJsonRpcMethod,
} from "./scenario-transport.js";
import {
  type LoadedScenario,
  loadScenarioSteps,
  loadScenarios,
  validateScenarios,
} from "./scenarios.js";

type ServerOptions = {
  appAri?: string;
  appId?: string;
  delay?: Delay;
  diagnostics?: Diagnostics;
  enableRealJiraCallbacks?: boolean;
  jiraFetch?: typeof fetch;
  jwksUrl?: string;
  logRequestData?: boolean;
  remoteLogger?: RemoteLogRecordLogger;
  scenarioDirectory?: string;
  scenarios?: LoadedScenario[];
};

const remoteLogger: RemoteLogRecordLogger = {
  debug: (record) => {
    if (verbose()) log.debug({ ...record }, record.message);
  },
  info: (record) => {
    if (verbose()) log.info({ ...record }, record.message);
  },
  warn: (record) => log.warn({ ...record }, record.message),
  error: (record) => log.error({ ...record }, record.message),
};

function jsonRpcMethod(body: unknown): string | undefined {
  if (typeof body !== "object" || body === null || !("method" in body))
    return undefined;
  return typeof body.method === "string" ? body.method : undefined;
}

// JSON-RPC errors (for example TaskNotFoundError from GetTask) reply with HTTP
// 200, so the "request completed" line alone cannot tell success from failure.
// This logs every non-streaming reply: errors always, and successful bodies
// (GetTask, SendMessage, CancelTask) when request-data logging is on. SSE
// `event: error` chunks are logged too. Secret-shaped keys are redacted.
function jsonRpcReplyDetails(body: object): Record<string, unknown> {
  const result = "result" in body ? body.result : undefined;
  if (typeof result !== "object" || result === null) return {};
  // SendMessage wraps the task as `result.task`; GetTask returns it directly.
  const task = "task" in result ? result.task : result;
  if (typeof task !== "object" || task === null) return {};
  const status =
    "status" in task && typeof task.status === "object" ? task.status : null;
  return {
    taskId: "id" in task ? task.id : undefined,
    contextId: "contextId" in task ? task.contextId : undefined,
    state: status && "state" in status ? status.state : undefined,
    artifactCount:
      "artifacts" in task && Array.isArray(task.artifacts)
        ? task.artifacts.length
        : undefined,
  };
}

// The status message text in a reply (the message shown to the user), if any.
function replyMessage(body: object): string | undefined {
  const result = "result" in body ? body.result : undefined;
  if (typeof result !== "object" || result === null) return undefined;
  const task = "task" in result ? result.task : result;
  if (typeof task !== "object" || task === null) return undefined;
  const status = "status" in task ? task.status : undefined;
  const message =
    typeof status === "object" && status !== null && "message" in status
      ? status.message
      : undefined;
  const parts =
    typeof message === "object" && message !== null && "parts" in message
      ? message.parts
      : undefined;
  if (!Array.isArray(parts)) return undefined;
  return parts
    .map((part) =>
      typeof part === "object" && part !== null && "text" in part
        ? String(part.text)
        : "",
    )
    .join("");
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {};
}

function firstLine(text: string | undefined): string | undefined {
  return text?.split("\n")[0] || undefined;
}

function logJsonRpcReplies(
  logBodies: () => boolean,
): (
  request: express.Request,
  response: express.Response,
  next: express.NextFunction,
) => void {
  return (request, response, next) => {
    const method = jsonRpcMethod(request.body);
    const report = (body: unknown) => {
      if (typeof body !== "object" || body === null) return;
      if ("error" in body && body.error) {
        log.warn(
          { jsonRpcMethod: method, jsonRpcError: redactSecrets(body) },
          "[remote → Jira] error response",
        );
      } else {
        // Always say what a non-streaming call answered with (GetTask,
        // SendMessage, CancelTask): the task and its current state.
        const details = jsonRpcReplyDetails(body);
        log.info(
          { ...details, message: firstLine(replyMessage(body)) },
          `[remote → Jira] ${method ?? "JSON-RPC"} response`,
        );
        if (verbose() && logBodies())
          log.info(
            {
              jsonRpcMethod: method,
              jsonRpcId: "id" in body ? body.id : undefined,
              ...details,
              jsonRpcResponse: redactSecrets(body),
            },
            "[remote → Jira] response body",
          );
      }
    };
    const json = response.json.bind(response);
    response.json = (body) => {
      report(body);
      return json(body);
    };
    const write = response.write.bind(response) as (
      ...args: unknown[]
    ) => boolean;
    // SubscribeToTask is an SSE stream: say once that it was accepted (with the
    // task's current state) and when it ends. A rejection arrives as an error
    // event, which `report` already logs.
    let subscribed = false;
    let acceptedAt = 0;
    const requestBody = record(request.body);
    // Identify the subscription on both lines: the task it watches and the
    // JSON-RPC id Jira gave this particular request.
    const subscription = {
      jsonRpcId: requestBody.id,
      taskId: record(requestBody.params).id,
    };
    if (method === "SubscribeToTask")
      response.on("close", () => {
        if (subscribed)
          log.info(
            {
              ...subscription,
              durationMs: Math.round(performance.now() - acceptedAt),
            },
            "[remote → Jira] SubscribeToTask stream ended",
          );
      });
    response.write = ((chunk: unknown, ...args: unknown[]) => {
      if (
        method === "SubscribeToTask" &&
        !subscribed &&
        typeof chunk === "string" &&
        !chunk.startsWith("event: error")
      ) {
        const data = chunk
          .split("\n")
          .find((line) => line.startsWith("data: "));
        try {
          if (data) {
            const body: unknown = JSON.parse(data.slice("data: ".length));
            if (typeof body === "object" && body !== null) {
              subscribed = true;
              acceptedAt = performance.now();
              log.info(
                {
                  jsonRpcId: subscription.jsonRpcId,
                  ...jsonRpcReplyDetails(body),
                  message: firstLine(replyMessage(body)),
                },
                "[remote → Jira] SubscribeToTask accepted",
              );
            }
          }
        } catch {
          // Not a JSON event; nothing to report.
        }
      }
      if (typeof chunk === "string" && chunk.startsWith("event: error")) {
        const data = chunk
          .split("\n")
          .find((line) => line.startsWith("data: "));
        try {
          if (data) report(JSON.parse(data.slice("data: ".length)));
        } catch {
          log.warn(
            { jsonRpcMethod: method },
            "[JSON-RPC] unparseable SSE error",
          );
        }
      }
      return write(chunk, ...args);
    }) as typeof response.write;
    next();
  };
}

// Says which way a diagnostic travelled: the remote answering Jira, the remote
// calling the Jira REST API, or Jira's REST reply coming back. Status lines use
// the A2A event name: the first step is published as the stream's initial
// `task` event, every later one (and a cancel) as a `statusUpdate` event.
function diagnosticLabel(event: DiagnosticEvent): string {
  switch (event.event) {
    case "agent-status":
      return event.step === 0
        ? "[remote → Jira] task"
        : "[remote → Jira] statusUpdate";
    case "agent-artifact":
      return "[remote → Jira] artifactUpdate";
    case "jira-callback":
      return "[remote → Jira API] callback";
    case "jira-response":
      return "[Jira API → remote] response";
    case "oauth-authorize":
    case "oauth-consent":
    case "oauth-token":
    case "oauth-check":
      return "[OAuth] connect flow";
    default:
      return "[A2A] diagnostic";
  }
}

const agentCard: AgentCard = {
  name: "Agent Simulator",
  description: "Simulates a completed task to verify the A2A connection.",
  supportedInterfaces: [
    {
      protocolBinding: "JSONRPC",
      protocolVersion: "1.0",
      tenant: "",
      url: "https://example.invalid/a2a/json-rpc",
    },
  ],
  provider: undefined,
  version: "1.0.0",
  capabilities: { extensions: [], streaming: true },
  securitySchemes: {},
  securityRequirements: [],
  defaultInputModes: ["text/plain"],
  defaultOutputModes: ["text/markdown"],
  skills: [],
  signatures: [],
};

// The configuration the remote resolved from its environment, for the startup
// log. An allowlist, so nothing secret can end up in it, and each value
// mirrors the expression the code itself uses.
export function startupConfiguration(
  env: NodeJS.ProcessEnv = process.env,
): Record<string, string | number | boolean> {
  return {
    port: Number(env.PORT ?? 3000),
    forgeAppId: env.FORGE_APP_ID ?? "(unset)",
    scenarioDirectory: env.SCENARIO_DIRECTORY ?? "(bundled)",
    realJiraCallbacks: env.ENABLE_REAL_JIRA_CALLBACK_SMOKE_TESTS === "true",
    logRequestData: env.LOG_AGENT_REQUEST_DATA !== "false",
    logFormat: env.LOG_FORMAT === "json" ? "json" : "pretty",
    logLevel: env.LOG_LEVEL ?? "(default)",
  };
}

export function createA2aServer({
  appId = process.env.FORGE_APP_ID,
  appAri = appId && `ari:cloud:ecosystem::app/${appId}`,
  delay = (milliseconds) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds)),
  diagnostics,
  enableRealJiraCallbacks = process.env
    .ENABLE_REAL_JIRA_CALLBACK_SMOKE_TESTS === "true",
  jiraFetch = fetch,
  jwksUrl = ATLASSIAN_FORGE_JWKS_URL,
  logRequestData,
  remoteLogger: configuredRemoteLogger = remoteLogger,
  scenarioDirectory = process.env.SCENARIO_DIRECTORY,
  scenarios,
}: ServerOptions = {}): Result<Express, ProblemDetails> {
  if (!appAri)
    return StandardError.getOrDefault(500).error("FORGE_APP_ID is required");

  let loadedScenarios: LoadedScenario[];
  try {
    loadedScenarios = scenarios
      ? validateScenarios(scenarios)
      : loadScenarios(scenarioDirectory);
  } catch (error) {
    return StandardError.getOrDefault(400).error(
      error instanceof Error ? error.message : "Invalid scenario collection",
    );
  }

  const reportDiagnostics =
    diagnostics ??
    ((rawEvent: DiagnosticEvent) => {
      const traceId = currentTraceId();
      const event = traceId ? { ...rawEvent, traceId } : rawEvent;
      if (event.event === "scenario.transport.mismatch")
        log.warn(event, "[A2A] diagnostic");
      else if (
        event.event === "agent-status" ||
        event.event === "agent-artifact" ||
        event.event === "jira-callback" ||
        event.event === "jira-response" ||
        String(event.event).startsWith("oauth-") ||
        event.event === "compliance-warning"
      ) {
        // Why a callback was simulated is useful only when debugging.
        const { simulatedBecause: _omitted, ...printed } = event;
        log.info(verbose() ? event : printed, diagnosticLabel(event));
      } else if (verbose()) log.info(event, "[A2A] diagnostic");
    });
  const oauth = createFakeOAuth({
    diagnostics: reportDiagnostics,
    origin: process.env.OAUTH_PUBLIC_BASE_URL,
  });
  const requestHandler = new DefaultRequestHandler(
    agentCard,
    new InMemoryTaskStore(),
    createScenarioRunner({
      scenarios: loadedScenarios,
      diagnostics: reportDiagnostics,
      delay,
      enableRealJiraCallbacks,
      jiraFetch,
      oauth,
      ...(logRequestData === undefined ? {} : { logRequestData }),
      remoteLogger: configuredRemoteLogger,
      transport: currentScenarioTransport,
      ...(scenarios
        ? {}
        : {
            loadSteps: (id) => loadScenarioSteps(id, scenarioDirectory),
          }),
    }),
  );
  const app = express();
  app.use(
    (
      request: express.Request,
      response: express.Response,
      next: express.NextFunction,
    ) => {
      const startedAt = performance.now();
      response.on("finish", () => {
        // Failures always log, so a request rejected before the handler (a FIT
        // failure returns 401, for example) is never silent. Successes log
        // only in verbose mode.
        const failed = response.statusCode >= 400;
        if (!failed && !verbose()) return;
        (failed ? log.warn : log.info).call(
          log,
          {
            durationMs: performance.now() - startedAt,
            method: request.method,
            path: request.path,
            statusCode: response.statusCode,
          },
          failed ? "[HTTP] request failed" : "[HTTP] request completed",
        );
      });
      // Jira (or the tunnel) hung up before the response finished. For a stream
      // this means later events have no reader, which is the thing to know when
      // a task seems stuck on the Jira side.
      response.on("close", () => {
        if (response.writableFinished) return;
        const body = record(request.body);
        const params = record(body.params);
        log.info(
          {
            durationMs: Math.round(performance.now() - startedAt),
            jsonRpcMethod: body.method,
            jsonRpcId: body.id,
            taskId: params.id ?? record(params.message).taskId,
            traceId: traceIdFromHeaders(request.headers),
          },
          "[Jira → remote] connection closed before the response finished",
        );
      });
      next();
    },
  );
  // Unauthenticated readiness probe: lets scripts/session.sh confirm the
  // remote is reachable through the tunnel before deploying Forge.
  app.get("/healthz", (_request, response) => {
    response.status(204).end();
  });
  // Browsers ask for this when the consent page opens; there is no icon, and
  // a 404 would log two warnings for nothing.
  app.get("/favicon.ico", (_request, response) => {
    response.status(204).end();
  });
  // Simulated OAuth provider (consent page and token endpoint). Public: the
  // user's browser calls it, not Jira, so it sits outside the FIT-protected path.
  app.use("/oauth", oauth.router);
  app.use(
    "/a2a/json-rpc",
    (
      _request: express.Request,
      _response: express.Response,
      next: express.NextFunction,
    ) => {
      if (verbose())
        log.info("[Forge Remote/FIT] invocation token validation started");
      next();
    },
    forgeRemoteAuthMiddleware({
      audience: appAri,
      issuer: "forge/invocation-token",
      jwksUrl,
    }),
    (
      request: express.Request,
      _response: express.Response,
      next: express.NextFunction,
    ) => {
      const remoteRequest = request as ForgeRemoteRequest;
      if (remoteRequest.forgeRemoteContext)
        emitRemoteLogRecord(
          configuredRemoteLogger,
          createRemoteAuthAcceptedRecord({
            context: remoteRequest.forgeRemoteContext,
          }),
        );
      if (verbose()) log.info("[Forge Remote/FIT] invocation token validated");
      // The tunnel/public origin Jira reached us on, for fake-OAuth links.
      const forwardedProto = request.headers["x-forwarded-proto"];
      oauth.rememberOrigin(
        `${(Array.isArray(forwardedProto) ? forwardedProto[0] : forwardedProto)?.split(",")[0] ?? request.protocol}://${request.headers.host ?? "localhost"}`,
      );
      next();
    },
    express.json(),
    (
      error: unknown,
      _request: express.Request,
      response: express.Response,
      next: express.NextFunction,
    ) => {
      if (error instanceof SyntaxError && "body" in error) {
        response.status(400).json({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Parse error" },
        });
      } else {
        next(error);
      }
    },
    (
      request: express.Request,
      _response: express.Response,
      next: express.NextFunction,
    ) =>
      runWithTraceId(traceIdFromHeaders(request.headers), () =>
        runWithScenarioTransport(
          transportForJsonRpcMethod(jsonRpcMethod(request.body)),
          next,
        ),
      ),
    (
      request: express.Request,
      _response: express.Response,
      next: express.NextFunction,
    ) => {
      // Raw JSON-RPC envelope Jira sent (id, method, params incl. message
      // and configuration); secret-shaped keys are redacted.
      if (logRequestData ?? process.env.LOG_AGENT_REQUEST_DATA !== "false")
        log.info(
          {
            traceId: traceIdFromHeaders(request.headers),
            jsonRpcRequest: redactSecrets(request.body),
          },
          "[Jira → remote] request body",
        );
      next();
    },
    (
      request: express.Request,
      _response: express.Response,
      next: express.NextFunction,
    ) => {
      if (verbose())
        log.info(
          {
            // Names only, never values: shows whether Jira sent
            // x-forge-oauth-user / x-forge-oauth-system.
            headerNames: Object.keys(request.headers).sort(),
            jsonRpcMethod: jsonRpcMethod(request.body),
            method: request.method,
            path: request.path,
          },
          "[HTTP] request received",
        );
      next();
    },
    (
      _request: express.Request,
      _response: express.Response,
      next: express.NextFunction,
    ) => {
      if (verbose()) log.info("[JSON-RPC] request dispatched to A2A handler");
      next();
    },
    logJsonRpcReplies(
      () => logRequestData ?? process.env.LOG_AGENT_REQUEST_DATA !== "false",
    ),
    jsonRpcHandler({
      requestHandler,
      userBuilder: forgeRemoteUserBuilder,
      contextBuilder: forgeRemoteServerCallContextBuilder(),
    }),
  );
  app.use((request, response) => {
    log.warn(
      { method: request.method, path: request.path },
      "[HTTP] request rejected: no matching route",
    );
    response.status(404).end();
  });
  return ok(app);
}
