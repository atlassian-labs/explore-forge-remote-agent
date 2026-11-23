import { randomUUID } from "node:crypto";
import express, { type Router } from "express";

// A simulated OAuth 2.0 authorization-code service, for demonstrating the A2A
// `auth-required` state end to end. Nothing here is real security: the consent
// page approves anyone who can reach it, and tokens live in memory. It exists
// so a scenario can wait for authorization and continue once it was granted.
//
// The scenario's task id is used as the OAuth `state`, which ties a browser
// approval back to the task that is waiting for it.

export type FakeOAuth = {
  authorizeUrl(state: string): string;
  isAuthorized(state: string): boolean;
  // Learns the public origin (for example the tunnel URL) from a trusted
  // request, so links in agent messages point at a reachable host.
  rememberOrigin(origin: string): void;
  router: Router;
};

type Diagnostic = (event: Record<string, unknown> & { event: string }) => void;

const scope = "agent:connect";

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (character) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[character] ?? character,
  );
}

function page(title: string, body: string): string {
  return `<!doctype html><meta charset="utf-8"><title>${escapeHtml(title)}</title>
<body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem">
<h1>${escapeHtml(title)}</h1>${body}</body>`;
}

export function createFakeOAuth({
  diagnostics = () => {},
  origin: configuredOrigin,
}: {
  diagnostics?: Diagnostic;
  origin?: string | undefined;
} = {}): FakeOAuth {
  let origin = configuredOrigin?.replace(/\/+$/, "") ?? "";
  // Single-use authorization codes, and the access token granted per state.
  const codes = new Map<string, string>();
  const tokens = new Map<string, { accessToken: string; scope: string }>();

  // The code-for-token exchange. Never log the token itself.
  const exchange = (code: string) => {
    const state = codes.get(code);
    if (state === undefined) return undefined;
    codes.delete(code);
    const grant = { accessToken: `fake-${randomUUID()}`, scope };
    tokens.set(state, grant);
    diagnostics({ event: "oauth-token", state, scope });
    return grant;
  };

  const router = express.Router();
  router.use(express.urlencoded({ extended: false }));

  router.get("/authorize", (request, response) => {
    const state = String(request.query.state ?? "");
    if (!state) {
      response.status(400).send(page("Missing state", "<p>No task given.</p>"));
      return;
    }
    diagnostics({ event: "oauth-authorize", state });
    response.send(
      page(
        "Agent Simulator wants access",
        `<p>The agent asks to connect to your account (<code>${scope}</code>).
This is a simulated consent screen.</p>
<form method="post" action="consent">
<input type="hidden" name="state" value="${escapeHtml(state)}">
<button name="decision" value="approve">Approve</button>
<button name="decision" value="deny">Deny</button>
</form>`,
      ),
    );
  });

  router.post("/consent", (request, response) => {
    const state = String(request.body?.state ?? "");
    const approved = request.body?.decision === "approve";
    diagnostics({
      event: "oauth-consent",
      state,
      decision: approved ? "approved" : "denied",
    });
    if (!state || !approved) {
      response.send(
        page(
          "Access denied",
          "<p>Nothing was granted. You can close this.</p>",
        ),
      );
      return;
    }
    const code = randomUUID();
    codes.set(code, state);
    response.redirect(
      `callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`,
    );
  });

  // Where a real provider would redirect the browser back to the app.
  router.get("/callback", (request, response) => {
    const grant = exchange(String(request.query.code ?? ""));
    response
      .status(grant ? 200 : 400)
      .send(
        grant
          ? page(
              "Connected",
              "<p>Authorization granted. You can close this page; the agent in Jira continues on its own.</p>",
            )
          : page("Invalid or used code", "<p>Start the connection again.</p>"),
      );
  });

  // The standard token endpoint, for clients that exchange the code themselves.
  router.post("/token", (request, response) => {
    const grant =
      request.body?.grant_type === "authorization_code"
        ? exchange(String(request.body?.code ?? ""))
        : undefined;
    if (!grant) {
      response.status(400).json({ error: "invalid_grant" });
      return;
    }
    response.json({
      access_token: grant.accessToken,
      token_type: "Bearer",
      scope: grant.scope,
    });
  });

  return {
    authorizeUrl: (state) =>
      `${origin}/oauth/authorize?state=${encodeURIComponent(state)}`,
    isAuthorized: (state) => tokens.has(state),
    rememberOrigin: (value) => {
      if (!configuredOrigin) origin = value.replace(/\/+$/, "");
    },
    router,
  };
}
