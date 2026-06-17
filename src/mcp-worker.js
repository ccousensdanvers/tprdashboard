import dashboardWorker from "./index.js";

const MCP_PROTOCOL_VERSION = "2025-06-18";
const MCP_PATH = "/mcp";
const MCP_SESSION_HEADER = "mcp-session-id";
const OAUTH_SCOPE = "mcp";
const SERVER_NAME = "thirdpartyrisk-mcp";
const SERVER_TITLE = "Third Party Risk UpGuard MCP";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

const DEFAULT_ALLOWED_ORIGINS = new Set([
  "https://chatgpt.com",
  "https://chat.openai.com",
  "https://playground.ai.cloudflare.com",
  "http://localhost:5173",
  "http://localhost:6274",
]);

const READ_ONLY_TOOLS = [
  {
    name: "get_upguard_dashboard_overview",
    title: "Get UpGuard Dashboard Overview",
    description: "Return the cached third-party risk dashboard overview from D1, including vendor counts, average score, active risk counts, top common risks, common categories, and last ingestion timestamps.",
    path: "/api/dashboard/overview",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "list_upguard_vendors",
    title: "List UpGuard Vendors",
    description: "Return the cached vendor/domain list with score, failed check count, waived check count, and scan timestamp.",
    path: "/api/vendors",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_upguard_vendor_detail",
    title: "Get UpGuard Vendor Detail",
    description: "Return cached domain, check result, waived check, active risk, and recent change detail for one vendor hostname.",
    pathFromArgs: (args) => `/api/vendor/${encodeURIComponent(requiredHostname(args))}`,
    inputSchema: {
      type: "object",
      properties: {
        hostname: { type: "string", description: "Vendor primary hostname or domain, for example 'adobe.com'." },
      },
      required: ["hostname"],
      additionalProperties: false,
    },
  },
  {
    name: "get_upguard_vendor_risks",
    title: "Get UpGuard Vendor Risks",
    description: "Return cached active UpGuard risks for one vendor hostname.",
    pathFromArgs: (args) => `/api/vendor/${encodeURIComponent(requiredHostname(args))}/risks`,
    inputSchema: {
      type: "object",
      properties: {
        hostname: { type: "string", description: "Vendor primary hostname or domain, for example 'adobe.com'." },
      },
      required: ["hostname"],
      additionalProperties: false,
    },
  },
  {
    name: "get_upguard_common_risks",
    title: "Get UpGuard Common Risks",
    description: "Return cached common portfolio risks with recommended action guidance.",
    path: "/api/dashboard/common-risks",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_upguard_remediation_campaigns",
    title: "Get UpGuard Remediation Campaigns",
    description: "Return cached remediation campaign groupings built from common and active risks.",
    path: "/api/dashboard/remediation-campaigns",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_upguard_recent_changes",
    title: "Get UpGuard Recent Changes",
    description: "Return cached recent UpGuard risk changes from the dashboard change feed.",
    path: "/api/dashboard/changes",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_upguard_ingestion_status",
    title: "Get UpGuard Ingestion Status",
    description: "Return cached ingestion status, row counts, latest run, recent runs, and recent ingestion errors.",
    path: "/api/ingest/status",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_upguard_severity_breakdown",
    title: "Get UpGuard Severity Breakdown",
    description: "Return cached failed check counts grouped by severity.",
    path: "/api/dashboard/severity-breakdown",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_upguard_categories",
    title: "Get UpGuard Categories",
    description: "Return cached failed check counts grouped by category.",
    path: "/api/dashboard/categories",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
];

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname.replace(/\/+$/, "") || "/";

    if (request.method === "OPTIONS") return empty({ status: 204, headers: corsHeaders(request, env, url) });
    if (pathname === "/.well-known/oauth-authorization-server" || pathname === "/.well-known/openid-configuration") return json(oauthServerMetadata(url));
    if (pathname === "/.well-known/oauth-protected-resource" || pathname === "/.well-known/oauth-protected-resource/mcp") return json(oauthProtectedResourceMetadata(url));
    if (pathname === "/register") return handleRegister(request);
    if (pathname === "/authorize") return handleAuthorize(request, env);
    if (pathname === "/token") return handleToken(request, env);
    if (pathname === MCP_PATH) return handleMcp(request, env, url);

    return dashboardWorker.fetch(request, env, ctx);
  },

  async scheduled(event, env, ctx) {
    if (typeof dashboardWorker.scheduled === "function") return dashboardWorker.scheduled(event, env, ctx);
  },
};

function json(data, init = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    ...init,
    headers: {
      ...JSON_HEADERS,
      ...(init.headers || {}),
    },
  });
}

function html(markup, init = {}) {
  return new Response(markup, {
    ...init,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      ...(init.headers || {}),
    },
  });
}

function empty(init = {}) {
  return new Response(null, init);
}

function origin(url) {
  return `${url.protocol}//${url.host}`;
}

function oauthServerMetadata(url) {
  const issuer = origin(url);
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [OAUTH_SCOPE],
    service_documentation: `${issuer}/api/health`,
  };
}

function oauthProtectedResourceMetadata(url) {
  const issuer = origin(url);
  return {
    resource: `${issuer}${MCP_PATH}`,
    authorization_servers: [issuer],
    scopes_supported: [OAUTH_SCOPE],
    bearer_methods_supported: ["header"],
  };
}

async function handleRegister(request) {
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, { status: 405, headers: { allow: "POST" } });
  let body = {};
  try {
    body = await request.json();
  } catch {}
  const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
  return json({
    client_id: `chatgpt-${crypto.randomUUID()}`,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris: redirectUris,
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    scope: OAUTH_SCOPE,
  });
}

function esc(value) {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function authorizeForm(params, error = "") {
  const fields = ["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "resource"];
  const hidden = fields.map((field) => `<input type="hidden" name="${field}" value="${esc(params.get(field) || "")}">`).join("\n");
  return html(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize UpGuard MCP</title></head>
<body style="font-family:system-ui,sans-serif;max-width:560px;margin:4rem auto;padding:0 1rem;line-height:1.45">
  <h1>Authorize UpGuard MCP</h1>
  <p>This will allow ChatGPT to read cached UpGuard third-party risk dashboard data.</p>
  ${error ? `<p style="color:#b00020"><strong>${esc(error)}</strong></p>` : ""}
  <form method="post" action="/authorize">
    ${hidden}
    <label>Admin password<br><input type="password" name="password" autocomplete="current-password" required style="width:100%;padding:.65rem;margin:.35rem 0 1rem"></label>
    <button type="submit" style="padding:.65rem 1rem">Authorize</button>
  </form>
</body>
</html>`);
}

async function handleAuthorize(request, env) {
  if (!env.OAUTH_ADMIN_PASSWORD) return html("OAuth is not configured. Set OAUTH_ADMIN_PASSWORD.", { status: 500 });
  if (request.method === "GET") return authorizeForm(new URL(request.url).searchParams);
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, { status: 405, headers: { allow: "GET, POST" } });

  const form = await request.formData();
  const params = new URLSearchParams();
  for (const key of ["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "resource"]) {
    const value = form.get(key);
    if (typeof value === "string") params.set(key, value);
  }

  if (form.get("password") !== env.OAUTH_ADMIN_PASSWORD) return authorizeForm(params, "Invalid password.");
  const redirectUri = params.get("redirect_uri");
  const codeChallenge = params.get("code_challenge");
  const codeChallengeMethod = params.get("code_challenge_method") || "S256";
  if (!redirectUri || !codeChallenge || codeChallengeMethod !== "S256") return authorizeForm(params, "Invalid OAuth request.");

  const code = await signPayload({
    typ: "auth_code",
    exp: Math.floor(Date.now() / 1000) + 300,
    client_id: params.get("client_id") || "",
    redirect_uri: redirectUri,
    code_challenge: codeChallenge,
    scope: params.get("scope") || OAUTH_SCOPE,
  }, env);

  const callback = new URL(redirectUri);
  callback.searchParams.set("code", code);
  const state = params.get("state");
  if (state) callback.searchParams.set("state", state);
  return Response.redirect(callback.toString(), 302);
}

async function handleToken(request, env) {
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, { status: 405, headers: { allow: "POST" } });
  const form = await request.formData();
  if (form.get("grant_type") !== "authorization_code") return json({ error: "unsupported_grant_type" }, { status: 400 });
  const code = form.get("code");
  const redirectUri = form.get("redirect_uri");
  const codeVerifier = form.get("code_verifier");
  if (typeof code !== "string" || typeof redirectUri !== "string" || typeof codeVerifier !== "string") return json({ error: "invalid_request" }, { status: 400 });

  const payload = await verifySignedPayload(code, env, "auth_code");
  if (!payload || payload.redirect_uri !== redirectUri || typeof payload.code_challenge !== "string") return json({ error: "invalid_grant" }, { status: 400 });
  const challenge = await sha256Base64Url(codeVerifier);
  if (challenge !== payload.code_challenge) return json({ error: "invalid_grant", error_description: "PKCE verification failed" }, { status: 400 });

  const accessToken = await signPayload({
    typ: "access_token",
    exp: Math.floor(Date.now() / 1000) + 3600,
    scope: OAUTH_SCOPE,
    client_id: typeof payload.client_id === "string" ? payload.client_id : "",
  }, env);

  return json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600, scope: OAUTH_SCOPE });
}

async function handleMcp(request, env, url) {
  if (request.method === "OPTIONS") return empty({ status: 204, headers: corsHeaders(request, env, url) });
  if (!(await verifyMcpBearer(request, env))) {
    const issuer = origin(url);
    return mcpJson(mcpError(null, -32001, "OAuth bearer token required."), request, env, url, { status: 401, headers: { "www-authenticate": `Bearer resource_metadata="${issuer}/.well-known/oauth-protected-resource/mcp"` } });
  }

  const requestSessionId = request.headers.get(MCP_SESSION_HEADER) || undefined;
  if (request.method === "GET") return mcpSse(request, env, url, requestSessionId);
  if (request.method === "DELETE") return empty({ status: 204, headers: mcpHeaders(request, env, url, requestSessionId) });
  if (request.method !== "POST") return mcpJson(mcpError(null, -32000, "Method not allowed."), request, env, url, { status: 405, headers: { allow: "GET, POST, DELETE, OPTIONS" } }, requestSessionId);

  let payload;
  try {
    payload = await request.json();
  } catch {
    return mcpJson(mcpError(null, -32700, "Parse error"), request, env, url, { status: 400 }, requestSessionId);
  }

  const firstMessage = Array.isArray(payload) ? payload[0] : payload;
  const isInitialize = firstMessage?.method === "initialize";
  const responseSessionId = requestSessionId || (isInitialize ? newSessionId() : undefined);

  if (Array.isArray(payload)) {
    const responses = (await Promise.all(payload.map((message) => handleMcpMessage(message, request, env)))).filter(Boolean);
    return responses.length ? mcpJson(responses, request, env, url, {}, responseSessionId) : empty({ status: 202, headers: mcpHeaders(request, env, url, responseSessionId) });
  }

  const response = await handleMcpMessage(payload, request, env);
  return response ? mcpJson(response, request, env, url, {}, responseSessionId) : empty({ status: 202, headers: mcpHeaders(request, env, url, responseSessionId) });
}

async function handleMcpMessage(message, request, env) {
  const id = message?.id;
  if (message?.jsonrpc !== "2.0" || typeof message.method !== "string") return mcpError(id, -32600, "Invalid Request");

  switch (message.method) {
    case "initialize":
      return mcpResult(id, { protocolVersion: MCP_PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: { name: SERVER_NAME, title: SERVER_TITLE, version: "0.1.0" } });
    case "notifications/initialized":
      return null;
    case "ping":
      return mcpResult(id, {});
    case "tools/list":
      return mcpResult(id, { tools: READ_ONLY_TOOLS.map(toToolDefinition) });
    case "tools/call":
      return handleToolCall(id, message.params, request, env);
    default:
      return mcpError(id, -32601, "Method not found");
  }
}

async function handleToolCall(id, params, request, env) {
  if (!params || typeof params.name !== "string") return mcpError(id, -32602, "Tool name is required.");
  const tool = READ_ONLY_TOOLS.find((candidate) => candidate.name === params.name);
  if (!tool) return mcpError(id, -32602, "Unknown tool requested.");
  const args = params.arguments && typeof params.arguments === "object" ? params.arguments : {};

  let path;
  try {
    path = typeof tool.pathFromArgs === "function" ? tool.pathFromArgs(args) : tool.path;
  } catch (error) {
    return mcpResult(id, { content: [{ type: "text", text: getErrorMessage(error) }], isError: true });
  }

  const result = await callDashboardJson(request, env, path);
  return mcpResult(id, {
    content: [{ type: "text", text: JSON.stringify(result.body, null, 2) }],
    structuredContent: result.body,
    isError: result.status >= 400,
  });
}

async function callDashboardJson(request, env, path) {
  const upstreamUrl = new URL(path, request.url);
  const upstreamRequest = new Request(upstreamUrl.toString(), {
    method: "GET",
    headers: { accept: "application/json" },
  });
  const response = await dashboardWorker.fetch(upstreamRequest, env, { waitUntil() {}, passThroughOnException() {} });
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = { error: "non_json_dashboard_response", status: response.status, body: text.slice(0, 2000) };
  }
  return { status: response.status, body };
}

function toToolDefinition(tool) {
  return {
    name: tool.name,
    title: tool.title,
    description: tool.description,
    inputSchema: tool.inputSchema,
  };
}

function requiredHostname(args) {
  const hostname = String(args.hostname || args.vendor_primary_hostname || "").trim().toLowerCase();
  if (!hostname) throw new Error("hostname is required.");
  return hostname;
}

function mcpError(id, code, message, data) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message, ...(data === undefined ? {} : { data }) } };
}

function mcpResult(id, result) {
  return { jsonrpc: "2.0", id: id ?? null, result };
}

function mcpJson(data, request, env, url, init = {}, sessionId) {
  return json(data, { ...init, headers: { ...mcpHeaders(request, env, url, sessionId), ...(init.headers || {}) } });
}

function mcpSse(request, env, url, sessionId) {
  const stream = new ReadableStream({
    start(controller) {
      const encoder = new TextEncoder();
      controller.enqueue(encoder.encode(": connected\n\n"));
      controller.enqueue(encoder.encode("event: endpoint\n"));
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ uri: `${origin(url)}${MCP_PATH}` })}\n\n`));
    },
  });
  return new Response(stream, {
    status: 200,
    headers: {
      ...mcpHeaders(request, env, url, sessionId || request.headers.get(MCP_SESSION_HEADER) || newSessionId()),
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    },
  });
}

function mcpHeaders(request, env, url, sessionId) {
  return {
    "mcp-protocol-version": MCP_PROTOCOL_VERSION,
    ...(sessionId ? { [MCP_SESSION_HEADER]: sessionId } : {}),
    ...corsHeaders(request, env, url),
  };
}

function corsHeaders(request, env, url) {
  const requestOrigin = request.headers.get("origin");
  const headers = {
    vary: "Origin",
    "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
    "access-control-allow-headers": "authorization, content-type, mcp-protocol-version, mcp-session-id, last-event-id",
    "access-control-expose-headers": "mcp-protocol-version, mcp-session-id, www-authenticate",
  };
  if (requestOrigin && allowedOrigins(env, origin(url)).has(requestOrigin)) headers["access-control-allow-origin"] = requestOrigin;
  return headers;
}

function allowedOrigins(env, workerOrigin) {
  const origins = new Set(DEFAULT_ALLOWED_ORIGINS);
  origins.add(workerOrigin);
  for (const value of String(env.ALLOWED_ORIGINS || "").split(",")) {
    const trimmed = value.trim();
    if (trimmed) origins.add(trimmed);
  }
  return origins;
}

function newSessionId() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function getBearerToken(request) {
  const header = request.headers.get("authorization");
  if (!header) return null;
  const [scheme, token] = header.split(" ");
  if (scheme?.toLowerCase() !== "bearer" || !token) return null;
  return token;
}

async function verifyMcpBearer(request, env) {
  const token = getBearerToken(request);
  if (!token) return false;
  if (env.MCP_API_TOKEN && token === env.MCP_API_TOKEN) return true;
  const payload = await verifySignedPayload(token, env, "access_token");
  return payload?.scope === OAUTH_SCOPE;
}

async function signPayload(payload, env) {
  const secret = oauthSigningSecret(env);
  if (!secret) throw new Error("OAuth signing secret is not configured.");
  const body = base64UrlEncodeString(JSON.stringify(payload));
  const signature = await hmacSha256(secret, body);
  return `${body}.${signature}`;
}

async function verifySignedPayload(token, env, typ) {
  const secret = oauthSigningSecret(env);
  if (!secret) return null;
  const [body, signature] = token.split(".");
  if (!body || !signature) return null;
  const expected = await hmacSha256(secret, body);
  if (signature !== expected) return null;
  let payload;
  try {
    payload = JSON.parse(base64UrlDecodeString(body));
  } catch {
    return null;
  }
  if (payload.typ !== typ) return null;
  if (typeof payload.exp !== "number" || payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

function oauthSigningSecret(env) {
  return env.OAUTH_TOKEN_SIGNING_SECRET || env.MCP_API_TOKEN || env.OAUTH_ADMIN_PASSWORD;
}

async function hmacSha256(secret, value) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return base64UrlEncode(new Uint8Array(signature));
}

async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64UrlEncode(new Uint8Array(digest));
}

function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlEncodeString(value) {
  return base64UrlEncode(new TextEncoder().encode(value));
}

function base64UrlDecodeString(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function getErrorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
