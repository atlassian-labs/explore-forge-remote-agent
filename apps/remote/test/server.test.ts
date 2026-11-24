import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer, type Server } from "node:http";
import test, { type TestContext } from "node:test";

import type {
  RemoteLogRecord,
  RemoteLogRecordLogger,
} from "@forge-ahead/remote/logging";
import type { LoadedScenario } from "../src/scenarios.js";
import { createA2aServer, startupConfiguration } from "../src/server.js";

type RequestOptions = {
  body: string;
  contentType?: string;
  path?: string;
  token?: string;
};
type CompletedResponse = {
  result: {
    task: {
      contextId: string;
      id: string;
      status: {
        message: {
          contextId: string;
          messageId: string;
          parts: unknown[];
          role: string;
          taskId: string;
        };
        state: string;
        timestamp: string;
      };
    };
  };
};
type DiagnosticEvent = Record<string, unknown>;
type Fixture = {
  baseUrl: string;
  request(options: RequestOptions): Promise<Response>;
  token(): string;
};

function base64url(value: string | object): string {
  return Buffer.from(
    typeof value === "string" ? value : JSON.stringify(value),
  ).toString("base64url");
}

async function signedFit(
  privateKey: Parameters<typeof crypto.subtle.sign>[1],
  payload: Record<string, unknown>,
): Promise<string> {
  const header = base64url({ alg: "RS256", kid: "test-key", typ: "JWT" });
  const body = base64url(payload);
  const signature = Buffer.from(
    await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      privateKey,
      new TextEncoder().encode(`${header}.${body}`),
    ),
  ).toString("base64url");
  return `${header}.${body}.${signature}`;
}

async function url(server: Server): Promise<string> {
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("server has no TCP address");
  return `http://127.0.0.1:${address.port}`;
}

async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => {
      if (
        (error as NodeJS.ErrnoException | undefined)?.code ===
        "ERR_SERVER_NOT_RUNNING"
      ) {
        resolve();
      } else if (error) {
        reject(error);
      } else {
        resolve();
      }
    }),
  );
}

async function createFixture(
  t: TestContext,
  {
    appAri = "app",
    appId,
    diagnostics,
    scenarios,
    enableRealJiraCallbacks,
    jiraFetch,
    logRequestData,
    remoteLogger,
    fitClaims = {},
  }: {
    appAri?: string;
    appId?: string;
    diagnostics?: (event: DiagnosticEvent) => void;
    scenarios?: LoadedScenario[];
    enableRealJiraCallbacks?: boolean;
    jiraFetch?: typeof fetch;
    logRequestData?: boolean;
    remoteLogger?: RemoteLogRecordLogger;
    fitClaims?: Record<string, unknown>;
  } = {},
): Promise<Fixture> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  if (!("privateKey" in keyPair)) throw new Error("expected RSA key pair");
  const publicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const audience = appId ? `ari:cloud:ecosystem::app/${appId}` : appAri;
  const token = await signedFit(keyPair.privateKey, {
    ...fitClaims,
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 60,
    iss: "forge/invocation-token",
  });
  const jwks = createServer((_, response) => {
    response.setHeader("content-type", "application/json");
    response.end(
      JSON.stringify({
        keys: [
          {
            ...publicKey,
            kid: "test-key",
            use: "sig",
            alg: "RS256",
          },
        ],
      }),
    );
  });
  jwks.listen(0, "127.0.0.1");
  const jwksUrl = `${await url(jwks)}/jwks`;
  t.after(() => close(jwks));

  const appResult = createA2aServer({
    ...(appId ? { appId } : { appAri }),
    delay: (milliseconds: number) =>
      new Promise((resolve) =>
        setTimeout(resolve, Math.min(milliseconds, 100)),
      ),
    jwksUrl,
    ...(diagnostics ? { diagnostics } : {}),
    ...(scenarios ? { scenarios } : {}),
    ...(enableRealJiraCallbacks ? { enableRealJiraCallbacks } : {}),
    ...(jiraFetch ? { jiraFetch } : {}),
    ...(logRequestData === undefined ? {} : { logRequestData }),
    ...(remoteLogger ? { remoteLogger } : {}),
  } as never);
  assert.equal(appResult.isOk(), true);
  if (appResult.isErr()) return assert.fail(appResult.error.detail);

  const server = appResult.value.listen(0, "127.0.0.1");
  const baseUrl = await url(server);
  t.after(() => close(server));

  return {
    baseUrl,
    token: () => token,
    request: ({
      token,
      body,
      path = "/a2a/json-rpc",
      contentType = "application/json",
    }: RequestOptions) =>
      fetch(`${baseUrl}${path}`, {
        method: "POST",
        headers: {
          ...(token ? { authorization: `Bearer ${token}` } : {}),
          "a2a-version": "1.0",
          "content-type": contentType,
          "x-forge-oauth-user": "validated-user-token",
        },
        body,
      }),
  };
}

test("returns a configuration error instead of throwing", () => {
  const result = createA2aServer({ appAri: "" });

  assert.equal(result.isErr(), true);
  if (result.isOk()) return assert.fail("expected a configuration error");
  assert.equal(result.error.status, 500);
  assert.equal(result.error.detail, "FORGE_APP_ID is required");
});

test("rejects a scenario collection without a default before accepting tasks", () => {
  const result = createA2aServer({ appId: "test", scenarios: [] });

  assert.equal(result.isErr(), true);
  if (result.isOk()) return assert.fail("expected a configuration error");
  assert.equal(result.error.status, 400);
  assert.match(result.error.detail ?? "", /exactly one Default Scenario/);
});

test("answers an unauthenticated health check so session scripts can probe readiness", async (t) => {
  const result = createA2aServer({ appAri: "app" });
  if (result.isErr()) return assert.fail(result.error.detail);
  const server = result.value.listen(0, "127.0.0.1");
  const baseUrl = await url(server);
  t.after(() => close(server));

  const response = await fetch(`${baseUrl}/healthz`);

  assert.equal(response.status, 204);
});

test("returns the default scenario task for a verified SendMessage request", async (t) => {
  const { request, token } = await createFixture(t, { appId: "test" });
  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "request-123",
      method: "SendMessage",
      params: {
        message: {
          contextId: "context-456",
          messageId: "message-123",
          role: "ROLE_USER",
          parts: [{ text: "do not echo this" }],
        },
      },
    }),
  });

  assert.equal(response.status, 200);
  const body = (await response.json()) as CompletedResponse & {
    id: string;
    jsonrpc: string;
  };
  assert.equal(body.jsonrpc, "2.0");
  assert.equal(body.id, "request-123");
  assert.ok(body.result, JSON.stringify(body));
  assert.equal(body.result.task.contextId, "context-456");
  assert.match(body.result.task.id, /^[0-9a-f-]{36}$/i);
  assert.equal(body.result.task.status.state, "TASK_STATE_COMPLETED");
  assert.deepEqual(body.result.task.status.message.parts, [
    {
      mediaType: "text/markdown",
      metadata: {},
      text: "**Finished the task.**",
    },
  ]);
  assert.equal(body.result.task.status.message.role, "ROLE_AGENT");
  assert.equal(body.result.task.status.message.taskId, body.result.task.id);
  assert.equal(body.result.task.status.message.contextId, "context-456");
  assert.match(body.result.task.status.message.messageId, /^[0-9a-f-]{36}$/i);
  assert.match(body.result.task.status.timestamp, /^\d{4}-\d{2}-\d{2}T/);
});

test("emits safe structured logs for authenticated completed tasks", async (t) => {
  const records: RemoteLogRecord[] = [];
  const remoteLogger: RemoteLogRecordLogger = {
    debug: (record) => records.push(record),
    info: (record) => records.push(record),
    warn: (record) => records.push(record),
    error: (record) => records.push(record),
  };
  const { request, token } = await createFixture(t, { remoteLogger });
  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "logging-request",
      method: "SendMessage",
      params: {
        message: {
          contextId: "logging-context",
          messageId: "logging-message",
          role: "ROLE_USER",
          parts: [{ text: "log this task" }],
        },
      },
    }),
  });

  assert.equal(response.status, 200);
  const completed = (await response.json()) as CompletedResponse;
  const auth = records.find(
    (record) => record.event === "remote.auth.accepted",
  );
  const terminal = records.find(
    (record) => record.event === "remote.a2a.completed",
  );
  assert.deepEqual(auth?.remoteContext.forwardedTokens, {
    hasSystemToken: false,
    hasUserToken: true,
  });
  assert.doesNotMatch(JSON.stringify(auth), /validated-user-token/);
  assert.deepEqual(terminal?.a2a, {
    contextId: "logging-context",
    final: true,
    state: "TASK_STATE_COMPLETED",
    taskId: completed.result.task.id,
  });
});

test("runs the default scenario for an unmatched SendMessage", async (t) => {
  const { request, token } = await createFixture(t);
  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "default-scenario",
      method: "SendMessage",
      params: {
        message: {
          contextId: "default-context",
          messageId: "default-message",
          role: "ROLE_USER",
          parts: [{ text: "A task without a matching scenario" }],
        },
      },
    }),
  });

  assert.equal(response.status, 200);
  const body = (await response.json()) as CompletedResponse;
  assert.equal(body.result.task.status.state, "TASK_STATE_COMPLETED");
  assert.deepEqual(body.result.task.status.message.parts, [
    {
      mediaType: "text/markdown",
      metadata: {},
      text: "**Finished the task.**",
    },
  ]);
});

test("selects the first case-insensitive matching scenario", async (t) => {
  const { request, token } = await createFixture(t);
  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "matched-scenario",
      method: "SendMessage",
      params: {
        message: {
          contextId: "match-context",
          messageId: "match-message",
          role: "ROLE_USER",
          parts: [{ text: "Please investigate the LOGIN FIX today" }],
        },
      },
    }),
  });

  assert.equal(response.status, 200);
  const body = (await response.json()) as CompletedResponse;
  assert.equal(body.result.task.status.state, "TASK_STATE_INPUT_REQUIRED");
  const statusMessage = JSON.stringify(body.result.task.status.message);
  assert.match(statusMessage, /Delivery plan ready for approval/);
  assert.match(statusMessage, /#### Goal/);
  assert.match(statusMessage, /Approve delivery plan/);
});

test("selects a scenario from a JSON-RPC Jira data part", async (t) => {
  const scenarios: LoadedScenario[] = [
    {
      id: "work-item",
      default: false,
      match: { contains: [], workItem: { id: "PROJ-42" } },
      steps: [
        {
          event: "status-update",
          state: "completed",
          message: "Matched the Jira work item.",
        },
      ],
    },
    {
      id: "default",
      default: true,
      match: { contains: [] },
      steps: [
        { event: "status-update", state: "completed", message: "Default." },
      ],
    },
  ];
  const { request, token } = await createFixture(t, { scenarios });
  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "jira-context",
      method: "SendMessage",
      params: {
        message: {
          contextId: "jira-context",
          messageId: "jira-message",
          role: "ROLE_USER",
          parts: [
            { text: "No matching text." },
            { data: { invocationContext: { workItem: { id: "PROJ-42" } } } },
          ],
        },
      },
    }),
  });

  assert.equal(response.status, 200);
  const body = (await response.json()) as CompletedResponse;
  assert.match(
    JSON.stringify(body.result.task.status.message.parts),
    /Matched the Jira work item/,
  );
});

test("emits safe correlated diagnostics for a selected scenario", async (t) => {
  const diagnostics: DiagnosticEvent[] = [];
  const { request, token } = await createFixture(t, {
    diagnostics: (event: DiagnosticEvent) => diagnostics.push(event),
    logRequestData: false,
    scenarios: [
      {
        id: "work-item",
        default: false,
        match: { contains: [], workItem: { id: "PROJ-42" } },
        steps: [{ event: "status-update", state: "completed" }],
      },
      {
        id: "default",
        default: true,
        match: { contains: [] },
        steps: [{ event: "status-update", state: "completed" }],
      },
    ],
  });
  const secret = "forge-token-secret";
  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "diagnostic-run",
      method: "SendMessage",
      params: {
        message: {
          contextId: "diagnostic-context",
          messageId: "diagnostic-message",
          role: "ROLE_USER",
          parts: [
            { text: "Ignore this unnecessary Jira content." },
            {
              data: {
                invocationContext: {
                  workItem: {
                    id: "PROJ-42",
                    fields: { summary: "Sensitive work-item summary" },
                  },
                  comment: { body: "Sensitive comment body" },
                  tenantId: "tenant-1",
                  invokerId: "user-1",
                  token: secret,
                },
              },
            },
          ],
        },
      },
    }),
  });

  assert.equal(response.status, 200);
  const task = (await response.json()) as CompletedResponse;
  const output = JSON.stringify(diagnostics);
  assert.ok(
    diagnostics.some(
      (event) =>
        event.event === "scenario-selected" &&
        event.taskId === task.result.task.id &&
        event.contextId === "diagnostic-context" &&
        event.scenarioId === "work-item" &&
        event.selection === "work-item" &&
        event.tenantId === "tenant-1" &&
        event.invokerId === "user-1" &&
        event.workItemAvailability === "available" &&
        event.commentAvailability === "available",
    ),
  );
  assert.ok(
    diagnostics.some(
      (event) =>
        event.event === "lifecycle" &&
        event.taskId === task.result.task.id &&
        event.state === "completed",
    ),
  );
  assert.equal(output.includes(secret), false);
  assert.equal(output.includes("Sensitive work-item summary"), false);
  assert.equal(output.includes("Sensitive comment body"), false);
});

test("logs the request data Jira shares with the agent, redacting tokens", async (t) => {
  const diagnostics: DiagnosticEvent[] = [];
  const { request, token } = await createFixture(t, {
    diagnostics: (event: DiagnosticEvent) => diagnostics.push(event),
    scenarios: [
      {
        id: "default",
        default: true,
        match: { contains: [] },
        steps: [{ event: "status-update", state: "completed" }],
      },
    ],
  });
  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "request-data-run",
      method: "SendMessage",
      params: {
        message: {
          contextId: "request-data-context",
          messageId: "request-data-message",
          role: "ROLE_USER",
          parts: [
            { text: "Please fix the login bug." },
            {
              data: {
                userAccountId: "user-account",
                agentAccountId: "agent-account",
                invocationType: "ISSUE_ASSIGNMENT",
                issue: {
                  id: "10001",
                  fields: {
                    key: "PROJ-1",
                    summary: "Login fails",
                    description: "Steps to reproduce",
                  },
                },
                token: "forge-token-secret",
              },
            },
          ],
        },
      },
    }),
  });

  assert.equal(response.status, 200);
  const logged = diagnostics.find((event) => event.event === "request-data");
  assert.ok(logged);
  assert.deepEqual(logged.texts, ["Please fix the login bug."]);
  const output = JSON.stringify(logged);
  for (const expected of [
    "user-account",
    "agent-account",
    "ISSUE_ASSIGNMENT",
    "PROJ-1",
    "Login fails",
    "Steps to reproduce",
  ])
    assert.ok(output.includes(expected), expected);
  assert.equal(output.includes("forge-token-secret"), false);
  assert.ok(
    diagnostics.some(
      (event) =>
        event.event === "agent-status" &&
        event.state === "TASK_STATE_COMPLETED",
    ),
  );
});

test("simulates a correlated Jira comment callback without mutating Jira", async (t) => {
  const diagnostics: DiagnosticEvent[] = [];
  const scenarios: LoadedScenario[] = [
    {
      id: "simulated-comment",
      default: true,
      match: { contains: [] },
      steps: [
        {
          event: "status-update",
          state: "working",
          message: "Preparing the Jira update.",
        },
        {
          event: "jira-callback",
          action: "comment",
          result: "simulated",
          message:
            "Simulated Jira comment update; no Jira comment was created.",
        } as unknown as LoadedScenario["steps"][number],
        {
          event: "status-update",
          state: "completed",
          message: "Finished the simulated callback.",
        },
      ],
    },
  ];
  const { request, token } = await createFixture(t, {
    diagnostics: (event) => diagnostics.push(event),
    scenarios,
  });
  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "simulated-comment",
      method: "SendStreamingMessage",
      params: {
        message: {
          contextId: "callback-context",
          messageId: "callback-message",
          role: "ROLE_USER",
          parts: [
            {
              data: {
                invocationContext: {
                  workItem: { id: "PROJ-42" },
                  tenantId: "tenant-1",
                  invokerId: "user-1",
                },
              },
            },
          ],
        },
      },
    }),
  });

  assert.equal(response.status, 200);
  assert.match(
    await response.text(),
    /Simulated Jira comment update; no Jira comment was created/,
  );
  assert.ok(
    diagnostics.some(
      (event) =>
        event.event === "jira-callback" &&
        event.action === "comment" &&
        event.result === "simulated" &&
        event.tenantId === "tenant-1" &&
        event.invokerId === "user-1" &&
        event.workItemId === "PROJ-42",
    ),
  );
});

test("reports every simulated Jira callback action with active invocation correlation", async (t) => {
  const diagnostics: DiagnosticEvent[] = [];
  const scenarios: LoadedScenario[] = [
    {
      id: "all-callbacks",
      default: true,
      match: { contains: [] },
      steps: [
        { event: "status-update", state: "working" },
        ...(["read", "comment", "mention", "transition"] as const).map(
          (action) => ({
            event: "jira-callback",
            action,
            result: "simulated" as const,
          }),
        ),
        { event: "status-update", state: "completed" },
      ],
    },
  ];
  const { request, token } = await createFixture(t, {
    diagnostics: (event) => diagnostics.push(event),
    scenarios,
  });
  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "all-callbacks",
      method: "SendStreamingMessage",
      params: {
        message: {
          contextId: "callbacks-context",
          messageId: "callbacks-message",
          role: "ROLE_USER",
          parts: [
            {
              data: {
                invocationContext: {
                  workItem: { id: "PROJ-42" },
                  tenantId: "tenant-1",
                  invokerId: "user-1",
                },
              },
            },
          ],
        },
      },
    }),
  });

  assert.equal(response.status, 200);
  const stream = await response.text();
  assert.ok(
    diagnostics.some(
      (event) =>
        event.event === "scenario-selected" && event.transport === "streaming",
    ),
  );
  for (const action of ["read", "comment", "mention", "transition"]) {
    assert.match(
      stream,
      new RegExp(`Simulated Jira ${action} callback \\(simulated\\)`),
    );
    assert.ok(
      diagnostics.some(
        (event) =>
          event.event === "jira-callback" &&
          event.action === action &&
          event.result === "simulated" &&
          event.tenantId === "tenant-1" &&
          event.invokerId === "user-1",
      ),
    );
  }
});

test("maps simulated callback outcomes and unavailable context to visible task results", async (t) => {
  const requestFor = async (
    t: TestContext,
    result: "auth-required" | "rejected" | "failed" | "simulated",
    context: Record<string, unknown>,
  ) => {
    const scenarios: LoadedScenario[] = [
      {
        id: `callback-${result}`,
        default: true,
        match: { contains: [] },
        steps: [
          { event: "status-update", state: "working" },
          { event: "jira-callback", action: "transition", result },
          { event: "status-update", state: "completed" },
        ],
      },
    ];
    const { request, token } = await createFixture(t, { scenarios });
    const response = await request({
      token: token(),
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: `callback-${result}`,
        method: "SendMessage",
        params: {
          message: {
            contextId: `callback-${result}-context`,
            messageId: `callback-${result}-message`,
            role: "ROLE_USER",
            parts: [{ data: { invocationContext: context } }],
          },
        },
      }),
    });
    assert.equal(response.status, 200);
    return JSON.stringify(await response.json());
  };
  const context = {
    workItem: { id: "PROJ-42" },
    tenantId: "tenant-1",
    invokerId: "user-1",
  };

  assert.match(
    await requestFor(t, "auth-required", context),
    /TASK_STATE_AUTH_REQUIRED/,
  );
  assert.match(await requestFor(t, "rejected", context), /TASK_STATE_REJECTED/);
  assert.match(await requestFor(t, "failed", context), /TASK_STATE_FAILED/);
  assert.match(
    await requestFor(t, "simulated", {
      tenantId: "tenant-1",
      invokerId: "user-1",
    }),
    /active invocation context is unavailable; no Jira action was performed/,
  );
});

test("runs explicitly enabled Jira callback smoke actions with validated identity", async (t) => {
  const calls: { body?: unknown; method?: string; url: string }[] = [];
  const events: DiagnosticEvent[] = [];
  const jiraFetch: typeof fetch = async (input, init) => {
    calls.push({
      url: String(input),
      ...(init?.method ? { method: init.method } : {}),
      ...(init?.body ? { body: JSON.parse(String(init.body)) } : {}),
    });
    if (String(input).endsWith("/transitions"))
      return Response.json({ transitions: [{ id: "31" }] });
    if (init?.method === "GET")
      return Response.json({
        key: "PROJ-42",
        fields: { summary: "Fix login", status: { name: "In Progress" } },
      });
    return new Response(null, { status: 204 });
  };
  const scenarios: LoadedScenario[] = [
    {
      id: "real-smoke",
      default: true,
      match: { contains: [] },
      steps: [
        { event: "jira-callback", action: "read", real: true },
        { event: "jira-callback", action: "comment", real: true },
        {
          event: "jira-callback",
          action: "transition",
          real: true,
          transitionId: "31",
        },
        { event: "status-update", state: "completed" },
      ] as LoadedScenario["steps"],
    },
  ];
  const { request, token } = await createFixture(t, {
    diagnostics: (event) => events.push(event),
    enableRealJiraCallbacks: true,
    fitClaims: {
      app: { apiBaseUrl: "https://jira.example.test" },
      context: { cloudId: "ari:cloud:jira::site/tenant-from-fit" },
      sub: "user-from-fit",
    },
    jiraFetch,
    scenarios,
  });
  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "real-smoke",
      method: "SendMessage",
      params: {
        message: {
          contextId: "real-smoke-context",
          messageId: "real-smoke-message",
          role: "ROLE_USER",
          parts: [
            {
              data: {
                invocationContext: {
                  workItem: { id: "PROJ-42" },
                  tenantId: "untrusted-tenant",
                  invokerId: "untrusted-user",
                },
              },
            },
          ],
        },
      },
    }),
  });

  assert.equal(response.status, 200);
  assert.equal(
    ((await response.json()) as CompletedResponse).result.task.status.state,
    "TASK_STATE_COMPLETED",
  );
  assert.deepEqual(
    calls.map(({ method, url }) => ({ method, url })),
    [
      {
        method: "GET",
        url: "https://jira.example.test/rest/api/3/issue/PROJ-42?fields=summary,status,labels",
      },
      {
        method: "POST",
        url: "https://jira.example.test/rest/api/3/issue/PROJ-42/comment",
      },
      {
        method: "POST",
        url: "https://jira.example.test/rest/api/3/issue/PROJ-42/transitions",
      },
    ],
  );
  assert.match(JSON.stringify(calls[1]?.body), /user-from-fit/);
  assert.deepEqual(calls[2]?.body, { transition: { id: "31" } });
  assert.deepEqual(
    events.find((event) => event.event === "jira-credentials")?.missing,
    [],
  );
  // The read is reported on the task and its response is logged.
  assert.ok(
    events.some(
      (event) =>
        event.event === "agent-status" &&
        event.source === "jira-callback" &&
        event.message ===
          "Read Jira work item PROJ-42: Fix login (status: In Progress).",
    ),
    JSON.stringify(events.filter((event) => event.source === "jira-callback")),
  );
  const logged = events.find(
    (event) => event.event === "jira-response" && event.action === "read",
  );
  assert.equal(logged?.httpStatus, 200);
  assert.deepEqual(logged?.body, {
    key: "PROJ-42",
    fields: { summary: "Fix login", status: { name: "In Progress" } },
  });
});

test("emits a terminal log when a Jira callback rejects a task", async (t) => {
  const records: RemoteLogRecord[] = [];
  const scenarios: LoadedScenario[] = [
    {
      id: "callback-rejected",
      default: true,
      match: { contains: [] },
      steps: [
        { event: "status-update", state: "working" },
        { event: "jira-callback", action: "transition", result: "rejected" },
      ],
    },
  ];
  const { request, token } = await createFixture(t, {
    remoteLogger: {
      debug: (record) => records.push(record),
      info: (record) => records.push(record),
      warn: (record) => records.push(record),
      error: (record) => records.push(record),
    },
    scenarios,
  });
  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "callback-rejected",
      method: "SendMessage",
      params: {
        message: {
          contextId: "callback-rejected-context",
          messageId: "callback-rejected-message",
          role: "ROLE_USER",
          parts: [
            {
              data: {
                invocationContext: {
                  workItem: { id: "PROJ-42" },
                  tenantId: "tenant-1",
                  invokerId: "user-1",
                },
              },
            },
          ],
        },
      },
    }),
  });

  assert.equal(response.status, 200);
  assert.equal(
    ((await response.json()) as CompletedResponse).result.task.status.state,
    "TASK_STATE_REJECTED",
  );
  assert.ok(
    records.some(
      (record) =>
        record.event === "remote.a2a.completed" &&
        record.a2a.state === "TASK_STATE_REJECTED" &&
        record.a2a.contextId === "callback-rejected-context",
    ),
  );
});

test("streams a coding delivery plan before requiring approval", async (t) => {
  const { request, token } = await createFixture(t);
  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "coding-stream",
      method: "SendStreamingMessage",
      params: {
        message: {
          contextId: "coding-context",
          messageId: "coding-message",
          role: "ROLE_USER",
          parts: [{ text: "Please investigate the login fix today" }],
        },
      },
    }),
  });

  assert.equal(response.status, 200);
  const stream = await response.text();
  const events = [
    "Delivery started",
    "Delivery plan ready for approval",
    "#### Goal",
  ];
  let previous = -1;
  for (const event of events) {
    const index = stream.indexOf(event);
    assert.ok(index > previous, `expected ${event} after the previous event`);
    previous = index;
  }
});

test("resumes a paused coding task over streaming", async (t) => {
  const { request, token } = await createFixture(t);
  const initial = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "coding-stream-start",
      method: "SendStreamingMessage",
      params: {
        message: {
          contextId: "coding-resume-context",
          messageId: "coding-stream-start-message",
          role: "ROLE_USER",
          parts: [{ text: "Please investigate the login fix today" }],
        },
      },
    }),
  });

  assert.equal(initial.status, 200);
  const initialStream = await initial.text();
  const taskId = /"id":"([^"]+)","contextId":"coding-resume-context"/.exec(
    initialStream,
  )?.[1];
  assert.ok(taskId, "expected the initial stream to include its task ID");
  assert.match(initialStream, /TASK_STATE_INPUT_REQUIRED/);

  const resumed = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "coding-stream-resume",
      method: "SendStreamingMessage",
      params: {
        message: {
          taskId,
          contextId: "coding-resume-context",
          messageId: "coding-stream-resume-message",
          role: "ROLE_USER",
          parts: [{ text: "Approve delivery plan" }],
        },
      },
    }),
  });

  assert.equal(resumed.status, 200);
  const stream = await resumed.text();
  assert.match(stream, /Repository analysis/);
  assert.match(stream, /Repository assessment/);
  assert.doesNotMatch(stream, /UnsupportedOperationError/);
});

test("resumes an initial input pause over streaming while the first stream is still open", async (t) => {
  const { request, token } = await createFixture(t);
  const send = (id: string, message: Record<string, unknown>) =>
    request({
      token: token(),
      body: JSON.stringify({
        jsonrpc: "2.0",
        id,
        method: "SendStreamingMessage",
        params: {
          message: {
            role: "ROLE_USER",
            messageId: `${id}-message`,
            ...message,
          },
        },
      }),
    });

  // Real Jira keeps this first request open after the pause, so read it
  // incrementally instead of waiting for it to end.
  const first = await send("initial-pause-start", {
    contextId: "initial-pause-context",
    parts: [{ text: "Please confirm the target environment" }],
  });
  const reader = first.body?.getReader();
  assert.ok(reader);
  const decoder = new TextDecoder();
  let firstStream = "";
  while (!/TASK_STATE_INPUT_REQUIRED/.test(firstStream)) {
    const chunk = await reader.read();
    assert.equal(chunk.done, false, "the first stream ended before the pause");
    firstStream += decoder.decode(chunk.value);
  }
  const taskId = /"id":"([^"]+)","contextId":"initial-pause-context"/.exec(
    firstStream,
  )?.[1];
  assert.ok(taskId, "expected the first stream to include its task ID");

  const resumed = await send("initial-pause-resume", {
    taskId,
    contextId: "initial-pause-context",
    parts: [{ text: "Env Dev" }],
  });
  const resumedStream = await resumed.text();

  // Drain what is left of the first stream (with a bound, so a stream that
  // never closes fails the test instead of hanging it).
  const deadline = Date.now() + 3000;
  for (;;) {
    const chunk = await Promise.race([
      reader.read(),
      new Promise<{ done: true; value?: undefined }>((resolve) =>
        setTimeout(() => resolve({ done: true }), 500),
      ),
    ]);
    if (chunk.done || Date.now() > deadline) break;
    firstStream += decoder.decode(chunk.value);
  }
  await reader.cancel().catch(() => undefined);

  assert.match(resumedStream, /TASK_STATE_COMPLETED/);
  assert.doesNotMatch(resumedStream, /ordering violation/);
  assert.doesNotMatch(firstStream, /ordering violation/);
});

test("returns the first Markdown example in an input-required prompt", async (t) => {
  const { request, token } = await createFixture(t);
  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "markdown-poll",
      method: "SendMessage",
      params: {
        message: {
          contextId: "markdown-context",
          messageId: "markdown-message",
          role: "ROLE_USER",
          parts: [{ text: "Please show markdown" }],
        },
      },
    }),
  });

  assert.equal(response.status, 200);
  const task = (await response.json()) as CompletedResponse;
  assert.equal(task.result.task.status.state, "TASK_STATE_INPUT_REQUIRED");
  const statusMessage = JSON.stringify(task.result.task.status.message);
  assert.match(statusMessage, /Markdown showcase/);
  assert.match(statusMessage, /Input required/);
  assert.doesNotMatch(statusMessage, /Bold text/);
  assert.match(statusMessage, /text\/markdown/);
});

test("streams rejected and failed scenarios with their correct terminal outcomes", async (t) => {
  const { request, token } = await createFixture(t);
  const stream = async (id: string, text: string) => {
    const response = await request({
      token: token(),
      body: JSON.stringify({
        jsonrpc: "2.0",
        id,
        method: "SendStreamingMessage",
        params: {
          message: {
            contextId: `${id}-context`,
            messageId: `${id}-message`,
            role: "ROLE_USER",
            parts: [{ text }],
          },
        },
      }),
    });
    assert.equal(response.status, 200);
    return response.text();
  };

  const rejected = await stream(
    "rejected",
    "For this experiment, reject now without processing the request.",
  );
  assert.match(rejected, /TASK_STATE_REJECTED/);
  assert.equal(rejected.includes("TASK_STATE_WORKING"), false);

  const failed = await stream(
    "failed",
    "Prepare the maintenance change for archived reports this week.",
  );
  const working = failed.indexOf("TASK_STATE_WORKING");
  const diagnostic = failed.indexOf("unapplied-patch-1");
  const terminal = failed.indexOf("TASK_STATE_FAILED");
  assert.ok(working >= 0 && diagnostic > working && terminal > diagnostic);
  assert.equal(
    failed.slice(terminal + 1).includes("TASK_STATE_WORKING"),
    false,
  );
});

test("returns a JSON-RPC error for a SendMessage request without a message", async (t) => {
  const { request, token } = await createFixture(t);
  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 7,
      method: "SendMessage",
      params: {},
    }),
  });

  assert.equal(response.status, 200);
  const body = (await response.json()) as {
    error: { code: number };
    id: number;
    jsonrpc: string;
  };
  assert.equal(body.jsonrpc, "2.0");
  assert.equal(body.id, 7);
  assert.equal(body.error.code, -32602);
});

test("rejects invalid requests and reports unsupported methods", async (t) => {
  const { request, token } = await createFixture(t);
  const validRequest = JSON.stringify({
    jsonrpc: "2.0",
    id: "id",
    method: "SendMessage",
    params: { message: {} },
  });

  assert.equal((await request({ body: "not json" })).status, 401);
  assert.equal(
    (await request({ token: token(), body: validRequest, path: "/wrong" }))
      .status,
    404,
  );
  const unsupportedContentType = await request({
    token: token(),
    body: validRequest,
    contentType: "text/plain",
  });
  assert.equal(unsupportedContentType.status, 200);
  assert.equal(
    ((await unsupportedContentType.json()) as { error: { code: number } }).error
      .code,
    -32005,
  );

  const malformed = await request({ token: token(), body: "not json" });
  assert.equal(malformed.status, 400);
  assert.equal(
    ((await malformed.json()) as { error: { code: number } }).error.code,
    -32700,
  );
  const unsupported = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 3,
      method: "UnknownMethod",
      params: {},
    }),
  });
  assert.equal(unsupported.status, 200);
  assert.deepEqual(await unsupported.json(), {
    jsonrpc: "2.0",
    id: 3,
    error: { code: -32601, message: "Invalid method." },
  });
});

test("creates fresh task and message IDs without echoing caller data", async (t) => {
  const { request, token } = await createFixture(t);
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "SendMessage",
    params: {
      message: {
        contextId: "",
        messageId: "message-789",
        role: "ROLE_USER",
        parts: [{ data: { secret: "never return" } }],
      },
    },
  });
  const [first, second] = await Promise.all([
    request({ token: token(), body }).then(
      async (response) => (await response.json()) as CompletedResponse,
    ),
    request({ token: token(), body }).then(
      async (response) => (await response.json()) as CompletedResponse,
    ),
  ]);

  assert.notEqual(first.result.task.id, second.result.task.id);
  assert.notEqual(
    first.result.task.status.message.messageId,
    second.result.task.status.message.messageId,
  );
  assert.notEqual(first.result.task.contextId, second.result.task.contextId);
  assert.equal(
    JSON.stringify(first.result.task.status.message).includes("never return"),
    false,
  );
});

test("resumes a clarification pause on the same task", async (t) => {
  const { request, token } = await createFixture(t);
  const initial = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "clarification-start",
      method: "SendMessage",
      params: {
        message: {
          contextId: "clarification-context",
          messageId: "clarification-start-message",
          role: "ROLE_USER",
          parts: [
            {
              text: "Please review the checkout criteria before implementation.",
            },
          ],
        },
      },
    }),
  });

  assert.equal(initial.status, 200);
  const paused = (await initial.json()) as CompletedResponse;
  assert.equal(paused.result.task.status.state, "TASK_STATE_INPUT_REQUIRED");
  assert.match(
    JSON.stringify(paused.result.task.status.message.parts),
    /guest checkout/i,
  );
  assert.match(JSON.stringify(paused.result.task), /checkout-plan-1/);

  const resumed = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "clarification-resume",
      method: "SendMessage",
      params: {
        message: {
          taskId: paused.result.task.id,
          contextId: paused.result.task.contextId,
          messageId: "clarification-resume-message",
          role: "ROLE_USER",
          parts: [{ text: "Guest checkout must be supported." }],
        },
      },
    }),
  });

  assert.equal(resumed.status, 200);
  const completed = (await resumed.json()) as CompletedResponse;
  assert.equal(completed.result.task.id, paused.result.task.id);
  assert.match(JSON.stringify(completed.result.task), /checkout-plan-1/);
  assert.equal(completed.result.task.status.state, "TASK_STATE_COMPLETED");
  assert.match(
    JSON.stringify(completed.result.task.status.message.parts),
    /clarified acceptance criteria/i,
  );
});

test("reports a repository connection configuration requirement", async (t) => {
  const { request, token } = await createFixture(t);
  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "connection-configuration-required",
      method: "SendMessage",
      params: {
        configuration: { returnImmediately: true },
        message: {
          contextId: "connection-configuration-context",
          messageId: "connection-configuration-message",
          role: "ROLE_USER",
          parts: [
            {
              text: "An administrator needs the repository connection configured.",
            },
          ],
        },
      },
    }),
  });

  assert.equal(response.status, 200);
  const task = (await response.json()) as CompletedResponse;
  assert.equal(task.result.task.status.state, "TASK_STATE_AUTH_REQUIRED");
  assert.match(
    JSON.stringify(task.result.task),
    /administrator must configure the repository connection/i,
  );
});

test("pauses before work for initial clarification and authorization", async (t) => {
  const { request, token } = await createFixture(t);
  for (const [state, prompt] of [
    [
      "TASK_STATE_INPUT_REQUIRED",
      "Confirm the target environment before the rollout",
    ],
    [
      "TASK_STATE_AUTH_REQUIRED",
      "Wait for repository approval before beginning deployment",
    ],
  ]) {
    const initial = await request({
      token: token(),
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: `${state}-start`,
        method: "SendMessage",
        params: {
          configuration: { returnImmediately: true },
          message: {
            contextId: `${state}-context`,
            messageId: `${state}-start-message`,
            role: "ROLE_USER",
            parts: [{ text: prompt }],
          },
        },
      }),
    });

    assert.equal(initial.status, 200);
    const paused = (await initial.json()) as CompletedResponse;
    assert.equal(paused.result.task.status.state, state);
    assert.equal(
      JSON.stringify(paused.result.task).includes("starting work"),
      false,
    );

    const resumed = await request({
      token: token(),
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: `${state}-resume`,
        method: "SendMessage",
        params: {
          message: {
            taskId: paused.result.task.id,
            contextId: paused.result.task.contextId,
            messageId: `${state}-resume-message`,
            role: "ROLE_USER",
            parts: [{ text: "Continue." }],
          },
        },
      }),
    });

    assert.equal(resumed.status, 200);
    const completed = (await resumed.json()) as CompletedResponse;
    assert.equal(completed.result.task.id, paused.result.task.id);
    assert.equal(completed.result.task.status.state, "TASK_STATE_COMPLETED");
  }
});

test("reports delayed scenario progress through GetTask polling", async (t) => {
  const scenarios: LoadedScenario[] = [
    {
      id: "polling-progress",
      default: true,
      match: { contains: [] },
      steps: [
        {
          event: "status-update",
          state: "working",
          message: "Started polling scenario.",
        },
        {
          event: "status-update",
          message: "Reached the delayed update.",
          delayMs: 100,
        },
        {
          event: "status-update",
          state: "completed",
          message: "Finished polling scenario.",
          delayMs: 100,
        },
      ],
    },
  ];
  const { request, token } = await createFixture(t, { scenarios });
  const send = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "polling-start",
      method: "SendMessage",
      params: {
        configuration: { returnImmediately: true },
        message: {
          contextId: "polling-context",
          messageId: "polling-message",
          role: "ROLE_USER",
          parts: [{ text: "Run the polling scenario." }],
        },
      },
    }),
  });

  assert.equal(send.status, 200);
  const started = (await send.json()) as CompletedResponse;
  assert.equal(started.result.task.status.state, "TASK_STATE_WORKING");
  assert.match(
    JSON.stringify(started.result.task.status.message.parts),
    /Started polling scenario/,
  );

  const task = async () => {
    const response = await request({
      token: token(),
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "polling-get-task",
        method: "GetTask",
        params: { id: started.result.task.id },
      }),
    });
    assert.equal(response.status, 200);
    return (await response.json()) as {
      result: CompletedResponse["result"]["task"];
    };
  };

  await new Promise((resolve) => setTimeout(resolve, 130));
  const progressed = await task();
  assert.equal(progressed.result.status.state, "TASK_STATE_WORKING");
  assert.match(
    JSON.stringify(progressed.result.status.message.parts),
    /Reached the delayed update/,
  );

  await new Promise((resolve) => setTimeout(resolve, 130));
  const completed = await task();
  assert.equal(completed.result.status.state, "TASK_STATE_COMPLETED");
  assert.match(
    JSON.stringify(completed.result.status.message.parts),
    /Finished polling scenario/,
  );
});

test("cancels delayed work after retaining its earlier artifact", async (t) => {
  const { request, token } = await createFixture(t);
  const started = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "cancel-start",
      method: "SendMessage",
      params: {
        configuration: { returnImmediately: true },
        message: {
          contextId: "cancel-context",
          messageId: "cancel-start-message",
          role: "ROLE_USER",
          parts: [
            {
              text: "Start the repository migration after the readiness review.",
            },
          ],
        },
      },
    }),
  });

  assert.equal(started.status, 200);
  const working = (await started.json()) as CompletedResponse;
  await new Promise((resolve) => setTimeout(resolve, 230));

  const canceled = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "cancel-task",
      method: "CancelTask",
      params: { id: working.result.task.id },
    }),
  });

  assert.equal(canceled.status, 200);
  const canceledTask = (await canceled.json()) as {
    result: CompletedResponse["result"]["task"];
  };
  assert.equal(canceledTask.result.status.state, "TASK_STATE_CANCELED");
  assert.match(JSON.stringify(canceledTask.result), /migration-progress-1/);

  await new Promise((resolve) => setTimeout(resolve, 250));
  const fetched = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "get-canceled-task",
      method: "GetTask",
      params: { id: working.result.task.id },
    }),
  });
  assert.equal(fetched.status, 200);
  const task = (await fetched.json()) as {
    result: CompletedResponse["result"]["task"];
  };
  assert.equal(task.result.status.state, "TASK_STATE_CANCELED");
  assert.equal(
    JSON.stringify(task.result).includes("TASK_STATE_COMPLETED"),
    false,
  );
});

test("GetTask returns the stored task after SendMessage", async (t) => {
  const { request, token } = await createFixture(t, { appId: "test" });
  const sent = (await (
    await request({
      token: token(),
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "send-1",
        method: "SendMessage",
        params: {
          message: {
            messageId: "message-get-1",
            role: "ROLE_USER",
            parts: [{ text: "hello" }],
          },
        },
      }),
    })
  ).json()) as CompletedResponse;

  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "get-1",
      method: "GetTask",
      params: { id: sent.result.task.id },
    }),
  });

  assert.equal(response.status, 200);
  const body = (await response.json()) as {
    error?: unknown;
    result?: { id: string; status: { state: string } };
  };
  assert.equal(body.error, undefined, JSON.stringify(body));
  assert.equal(body.result?.id, sent.result.task.id);
  assert.equal(body.result?.status.state, "TASK_STATE_COMPLETED");
});

test("logs the JSON-RPC error body when GetTask cannot find the task", async (t) => {
  const warn = t.mock.method(console, "warn", () => {});
  const { request, token } = await createFixture(t, { appId: "test" });

  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "get-missing",
      method: "GetTask",
      params: { id: "00000000-0000-4000-8000-000000000000" },
    }),
  });

  // JSON-RPC errors reply with HTTP 200; only the body says it failed.
  assert.equal(response.status, 200);
  const body = (await response.json()) as { error?: { message: string } };
  assert.ok(body.error, JSON.stringify(body));

  const logged = warn.mock.calls
    .map((call) => String(call.arguments[0]))
    .find((line) => line.includes("[remote → Jira] error response"));
  assert.ok(logged, "expected an error-response log line");
  assert.match(logged, /jsonRpcMethod=GetTask/);
  assert.ok(logged.includes(body.error.message), logged);
});

test("logs the body of a successful GetTask reply, and not when request logging is off", async (t) => {
  for (const [logRequestData, expected] of [
    [true, true],
    [false, false],
  ] as const) {
    process.env.LOG_VERBOSE = "true";
    t.after(() => {
      delete process.env.LOG_VERBOSE;
    });
    const info = t.mock.method(console, "info", () => {});
    const { request, token } = await createFixture(t, { logRequestData });
    const call = async (id: string, method: string, params: object) =>
      request({
        token: token(),
        body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
      });
    const sent = (await (
      await call(`send-${logRequestData}`, "SendMessage", {
        message: {
          role: "ROLE_USER",
          messageId: `m-${logRequestData}`,
          parts: [{ text: "hello" }],
        },
      })
    ).json()) as CompletedResponse;
    await call(`get-${logRequestData}`, "GetTask", {
      id: sent.result.task.id,
    });

    const line = info.mock.calls
      .map((entry) => String(entry.arguments[0]))
      .find(
        (text) =>
          text.includes("[remote → Jira] response body") &&
          text.includes("jsonRpcMethod=GetTask"),
      );
    if (expected) {
      assert.ok(line, "expected a GetTask response log line");
      assert.match(line, new RegExp(`taskId=${sent.result.task.id}`));
      assert.match(line, /state=TASK_STATE_COMPLETED/);
      assert.ok(line.includes("Finished the task."), line);
    } else {
      assert.equal(line, undefined);
    }
    info.mock.restore();
  }
});

test("logs the x-b3-traceid header on the request and on agent-status lines", async (t) => {
  const info = t.mock.method(console, "info", () => {});
  const { baseUrl, token } = await createFixture(t);
  const response = await fetch(`${baseUrl}/a2a/json-rpc`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token()}`,
      "a2a-version": "1.0",
      "content-type": "application/json",
      "x-b3-traceid": "trace-abc-123",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "traced",
      method: "SendStreamingMessage",
      params: {
        message: {
          role: "ROLE_USER",
          messageId: "m-traced",
          parts: [{ text: "hello" }],
        },
      },
    }),
  });
  await response.text();

  const lines = info.mock.calls.map((entry) => String(entry.arguments[0]));
  assert.ok(
    lines.some(
      (line) =>
        line.includes("[Jira → remote] request body") &&
        line.includes("traceId=trace-abc-123"),
    ),
    "expected the request body line to carry the trace ID",
  );
  assert.ok(
    lines.some(
      (line) =>
        line.includes("event=agent-status") &&
        line.includes("traceId=trace-abc-123"),
    ),
    "expected agent-status lines to carry the trace ID",
  );
});

test("logs the task state in the reply to GetTask without verbose logging", async (t) => {
  const info = t.mock.method(console, "info", () => {});
  const { request, token } = await createFixture(t);
  const call = async (id: string, method: string, params: object) =>
    request({
      token: token(),
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    });
  const sent = (await (
    await call("send", "SendMessage", {
      message: {
        role: "ROLE_USER",
        messageId: "m-get",
        parts: [{ text: "hello" }],
      },
    })
  ).json()) as CompletedResponse;
  await call("get", "GetTask", { id: sent.result.task.id });

  const line = info.mock.calls
    .map((entry) => String(entry.arguments[0]))
    .find((text) => text.includes("[remote → Jira] GetTask response"));
  assert.ok(line, "expected a GetTask response line");
  assert.match(line, new RegExp(`taskId=${sent.result.task.id}`));
  assert.match(line, /state=TASK_STATE_COMPLETED/);
  assert.ok(line.includes("Finished the task."), line);
  assert.equal(
    info.mock.calls.some((entry) =>
      String(entry.arguments[0]).includes("[remote → Jira] response body"),
    ),
    false,
  );
});

test("logs when SubscribeToTask is accepted for a running task and when it is rejected", async (t) => {
  const info = t.mock.method(console, "info", () => {});
  const warn = t.mock.method(console, "warn", () => {});
  const scenarios: LoadedScenario[] = [
    {
      id: "slow",
      default: true,
      match: { contains: [] },
      steps: [
        { event: "status-update", state: "working", message: "Started." },
        ...Array.from({ length: 6 }, (_, index) => ({
          event: "status-update" as const,
          message: `Step ${index + 1}.`,
          delayMs: 100,
        })),
        {
          event: "status-update",
          state: "completed",
          message: "Done.",
          final: true,
          delayMs: 100,
        },
      ],
    },
  ];
  const { baseUrl, token } = await createFixture(t, { scenarios });
  const post = (body: object) =>
    fetch(`${baseUrl}/a2a/json-rpc`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token()}`,
        "a2a-version": "1.0",
        "content-type": "application/json",
      },
      body: JSON.stringify({ jsonrpc: "2.0", ...body }),
    });

  const started = await post({
    id: "start",
    method: "SendStreamingMessage",
    params: {
      message: {
        role: "ROLE_USER",
        messageId: "m-sub",
        parts: [{ text: "hello" }],
      },
    },
  });
  const reader = started.body?.getReader();
  assert.ok(reader);
  const first = new TextDecoder().decode((await reader.read()).value);
  const dataLine = first.split("\n").find((line) => line.startsWith("data: "));
  assert.ok(dataLine, first);
  const taskId = (
    JSON.parse(dataLine.slice("data: ".length)) as {
      result: { task: { id: string } };
    }
  ).result.task.id;

  const subscribed = await post({
    id: "sub",
    method: "SubscribeToTask",
    params: { id: taskId },
  });
  await subscribed.text();
  await reader.cancel().catch(() => {});

  const lines = info.mock.calls.map((entry) => String(entry.arguments[0]));
  assert.ok(
    lines.some(
      (line) =>
        line.includes("[remote → Jira] SubscribeToTask accepted") &&
        line.includes(`taskId=${taskId}`),
    ),
    "expected an accepted line",
  );
  assert.ok(
    lines.some(
      (line) =>
        line.includes("[remote → Jira] SubscribeToTask stream ended") &&
        line.includes(`taskId=${taskId}`) &&
        line.includes("jsonRpcId=sub") &&
        line.includes("durationMs="),
    ),
    "expected a stream-ended line",
  );

  // The task is terminal now, so a second subscribe is rejected.
  const rejected = await post({
    id: "sub-2",
    method: "SubscribeToTask",
    params: { id: taskId },
  });
  await rejected.text();
  assert.ok(
    warn.mock.calls.some(
      (entry) =>
        String(entry.arguments[0]).includes("[remote → Jira] error response") &&
        String(entry.arguments[0]).includes("jsonRpcMethod=SubscribeToTask"),
    ),
    "expected a rejection warning",
  );
});

test("logs artifact updates by default", async (t) => {
  const info = t.mock.method(console, "info", () => {});
  const scenarios: LoadedScenario[] = [
    {
      id: "with-artifact",
      default: true,
      match: { contains: [] },
      steps: [
        { event: "status-update", state: "working", message: "Started." },
        {
          event: "artifact-update",
          artifact: {
            artifactId: "log-1",
            name: "Progress log",
            parts: [{ kind: "text", text: "- collected input" }],
          },
        },
        {
          event: "status-update",
          state: "completed",
          message: "Done.",
          final: true,
        },
      ],
    },
  ];
  const { request, token } = await createFixture(t, { scenarios });
  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "artifact",
      method: "SendStreamingMessage",
      params: {
        message: {
          role: "ROLE_USER",
          messageId: "m-artifact",
          parts: [{ text: "hello" }],
        },
      },
    }),
  });
  await response.text();

  const line = info.mock.calls
    .map((entry) => String(entry.arguments[0]))
    .find((text) => text.includes("[remote → Jira] artifactUpdate"));
  assert.ok(line, "expected an artifactUpdate line");
  assert.match(line, /artifactId=log-1/);
  assert.match(line, /scenarioId=with-artifact/);
  assert.ok(line.includes("- collected input"), line);
});

test("runs a simulated Jira callback for Jira's real payload shape", async (t) => {
  const scenarios: LoadedScenario[] = [
    {
      id: "jira-shaped-callback",
      default: true,
      match: { contains: [] },
      steps: [
        { event: "status-update", state: "working", message: "Started." },
        { event: "jira-callback", action: "read" },
        { event: "status-update", state: "completed", message: "Done." },
      ],
    },
  ];
  const events: DiagnosticEvent[] = [];
  const { request, token } = await createFixture(t, {
    diagnostics: (event) => events.push(event),
    scenarios,
  });

  const response = await request({
    token: token(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "jira-shaped",
      method: "SendMessage",
      params: {
        message: {
          contextId: "jira-shaped-context",
          messageId: "jira-shaped-message",
          role: "ROLE_USER",
          parts: [
            { text: "You have been assigned to a work item." },
            {
              data: {
                userAccountId: "557057:user",
                agentAccountId: "712020:agent",
                issue: { id: "66408", fields: { key: "MOBL-58" } },
                invocationType: "ISSUE_ASSIGNMENT",
              },
            },
          ],
        },
      },
    }),
  });

  assert.equal(response.status, 200);
  const body = JSON.stringify(await response.json());
  assert.doesNotMatch(body, /invocation context is unavailable/);
  assert.match(body, /TASK_STATE_COMPLETED/);
  const credentials = events.find(
    (event) => event.event === "jira-credentials",
  );
  assert.equal(credentials?.available, false);
  assert.deepEqual(credentials?.missing, [
    "fit.app.apiBaseUrl",
    "fit.principal",
    "tenant (fit.context.cloudId)",
  ]);
  // The log says why the callback was simulated.
  assert.deepEqual(
    events.find((event) => event.event === "jira-callback")?.simulatedBecause,
    ["env-flag-off", "step-not-real", "no-forge-user-token-or-tenant"],
  );
});

test("startup configuration reports resolved settings and nothing else", () => {
  assert.deepEqual(
    startupConfiguration({
      ENABLE_REAL_JIRA_CALLBACK_SMOKE_TESTS: "true",
      FORGE_APP_ID: "app-1",
      LOG_AGENT_REQUEST_DATA: "false",
      LOG_FORMAT: "json",
      PORT: "4000",
      SECRET_TOKEN: "do-not-log",
    }),
    {
      port: 4000,
      forgeAppId: "app-1",
      scenarioDirectory: "(bundled)",
      realJiraCallbacks: true,
      logRequestData: false,
      logFormat: "json",
      logLevel: "(default)",
    },
  );
  assert.deepEqual(startupConfiguration({}), {
    port: 3000,
    forgeAppId: "(unset)",
    scenarioDirectory: "(bundled)",
    realJiraCallbacks: false,
    logRequestData: true,
    logFormat: "pretty",
    logLevel: "(default)",
  });
});

test("waits in auth-required for fake OAuth and continues without a reply once approved", async (t) => {
  const { baseUrl, request, token } = await createFixture(t);
  const call = async (id: string, method: string, params: object) => {
    const response = await request({
      token: token(),
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    });
    const body = (await response.json()) as {
      result: CompletedResponse["result"]["task"] & {
        task?: CompletedResponse["result"]["task"];
      };
    };
    // SendMessage wraps the task in `result.task`; GetTask returns it directly.
    return body.result.task ?? body.result;
  };

  const waiting = await call("connect-start", "SendMessage", {
    message: {
      role: "ROLE_USER",
      messageId: "connect-start",
      contextId: "connect-context",
      parts: [{ text: "Please connect to agent" }],
    },
  });
  assert.equal(waiting.status.state, "TASK_STATE_AUTH_REQUIRED");
  const link = JSON.stringify(waiting.status.message).match(
    /\/oauth\/authorize\?state=([\w-]+)/,
  );
  assert.ok(link, "the message links to the consent page");
  const state = link[1] ?? "";
  assert.equal(state, waiting.id);
  assert.doesNotMatch(JSON.stringify(waiting.status.message), /reply/i);

  const getTask = () => call("connect-poll", "GetTask", { id: waiting.id });
  // Not approved yet: the task is still waiting, not failed or completed.
  assert.equal((await getTask()).status.state, "TASK_STATE_AUTH_REQUIRED");

  // The consent routes are public (no FIT): the user's browser calls them.
  const consentPage = await fetch(`${baseUrl}/oauth/authorize?state=${state}`);
  assert.equal(consentPage.status, 200);
  assert.match(await consentPage.text(), /wants access/);
  const consent = await fetch(`${baseUrl}/oauth/consent`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ state, decision: "approve" }),
  });
  assert.equal(consent.status, 302);
  const callback = await fetch(
    new URL(consent.headers.get("location") ?? "", `${baseUrl}/oauth/consent`),
  );
  assert.equal(callback.status, 200);
  assert.match(await callback.text(), /Connected/);

  // No reply is sent: the same task completes by itself.
  let finalState = "";
  for (
    let attempt = 0;
    attempt < 60 && finalState !== "TASK_STATE_COMPLETED";
    attempt++
  ) {
    await new Promise((resolve) => setTimeout(resolve, 50));
    finalState = (await getTask()).status.state;
  }
  assert.equal(finalState, "TASK_STATE_COMPLETED");
});

test("a message sent to a task waiting for authorization does not skip the authorization", async (t) => {
  const { baseUrl, request, token } = await createFixture(t);
  const call = async (id: string, method: string, params: object) => {
    const response = await request({
      token: token(),
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    });
    const body = (await response.json()) as {
      result: CompletedResponse["result"]["task"] & {
        task?: CompletedResponse["result"]["task"];
      };
    };
    return body.result.task ?? body.result;
  };

  const waiting = await call("skip-start", "SendMessage", {
    message: {
      role: "ROLE_USER",
      messageId: "skip-start",
      contextId: "skip-context",
      parts: [{ text: "Please connect to agent" }],
    },
  });
  assert.equal(waiting.status.state, "TASK_STATE_AUTH_REQUIRED");

  // The spec says agents SHOULD accept messages for a task in AUTH_REQUIRED.
  // Doing so must not run the later steps before the user has approved.
  const early = await call("skip-early", "SendMessage", {
    message: {
      role: "ROLE_USER",
      messageId: "skip-early",
      taskId: waiting.id,
      contextId: waiting.contextId,
      parts: [{ text: "Continue" }],
    },
  });
  assert.equal(early.status.state, "TASK_STATE_AUTH_REQUIRED");
  assert.match(JSON.stringify(early.status.message), /oauth\/authorize/);
  await new Promise((resolve) => setTimeout(resolve, 400));
  const stillWaiting = await call("skip-poll", "GetTask", { id: waiting.id });
  assert.equal(stillWaiting.status.state, "TASK_STATE_AUTH_REQUIRED");

  // Approving still lets the original wait finish the task.
  const consent = await fetch(`${baseUrl}/oauth/consent`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ state: waiting.id, decision: "approve" }),
  });
  await fetch(
    new URL(consent.headers.get("location") ?? "", `${baseUrl}/oauth/consent`),
  );
  let finalState = "";
  for (
    let attempt = 0;
    attempt < 60 && finalState !== "TASK_STATE_COMPLETED";
    attempt++
  ) {
    await new Promise((resolve) => setTimeout(resolve, 50));
    finalState = (await call("skip-final", "GetTask", { id: waiting.id }))
      .status.state;
  }
  assert.equal(finalState, "TASK_STATE_COMPLETED");
});

test("a streamed message to a task waiting for authorization gets the pending status", async (t) => {
  const { request, token } = await createFixture(t);
  const send = (id: string, message: Record<string, unknown>) =>
    request({
      token: token(),
      body: JSON.stringify({
        jsonrpc: "2.0",
        id,
        method: "SendStreamingMessage",
        params: {
          message: {
            role: "ROLE_USER",
            messageId: `${id}-message`,
            ...message,
          },
        },
      }),
    });
  // The first stream stays open in auth-required, as it does with Jira.
  const first = await send("stream-auth-start", {
    contextId: "stream-auth-context",
    parts: [{ text: "Please connect to agent" }],
  });
  const reader = first.body?.getReader();
  assert.ok(reader);
  const decoder = new TextDecoder();
  let firstStream = "";
  while (!/oauth\/authorize/.test(firstStream)) {
    const chunk = await reader.read();
    assert.equal(chunk.done, false, "the first stream ended early");
    firstStream += decoder.decode(chunk.value);
  }
  const taskId = /"id":"([^"]+)","contextId":"stream-auth-context"/.exec(
    firstStream,
  )?.[1];
  assert.ok(taskId);

  const second = await Promise.race([
    send("stream-auth-message", {
      taskId,
      contextId: "stream-auth-context",
      parts: [{ text: "Continue" }],
    }).then((response) => response.text()),
    new Promise<string>((resolve) =>
      setTimeout(() => resolve("TIMEOUT"), 3000),
    ),
  ]);
  await reader.cancel().catch(() => undefined);

  assert.doesNotMatch(second, /ordering violation|before initial/);
  assert.doesNotMatch(second, /TASK_STATE_COMPLETED/);
  assert.doesNotMatch(firstStream, /ordering violation/);
});

test("fake OAuth rejects a reused or unknown authorization code", async (t) => {
  const { baseUrl } = await createFixture(t);
  const replay = await fetch(`${baseUrl}/oauth/callback?code=never-issued`);
  assert.equal(replay.status, 400);
  const token = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: "never-issued",
    }),
  });
  assert.equal(token.status, 400);
  assert.deepEqual(await token.json(), { error: "invalid_grant" });
});
