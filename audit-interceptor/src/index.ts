import http from "node:http";
import fs from "node:fs";
import { ulid } from "ulid";
import { request } from "undici";
import { decodeJwt, extractActor } from "./jwt.js";
import { redact, redactHeaders } from "./redact.js";
import { LldapClient } from "./lldap-client.js";
import { MUTATIONS, looksLikeMutation, resolvePath, type MutationSpec } from "./mutations.js";

const PORT = Number(process.env.PORT ?? 8080);
const LLDAP_UPSTREAM = process.env.LLDAP_UPSTREAM ?? "http://lldap:17170";
const SERVICE_ACCOUNT_USERNAME = process.env.SERVICE_ACCOUNT_USERNAME ?? "iyagi_audit_interceptor";
const SERVICE_ACCOUNT_PASSWORD_FILE =
  process.env.SERVICE_ACCOUNT_PASSWORD_FILE ?? "/run/secrets/audit-interceptor-password";
const HEARTBEAT_INTERVAL_MS = Number(process.env.HEARTBEAT_INTERVAL_MS ?? 60_000);

function loadPassword(): string {
  try {
    return fs.readFileSync(SERVICE_ACCOUNT_PASSWORD_FILE, "utf8").trim();
  } catch (e) {
    emit({
      event_type: "audit.error",
      error: `service account password unreadable: ${(e as Error).message}`,
    });
    return "";
  }
}

const lldap = new LldapClient({
  baseUrl: LLDAP_UPSTREAM,
  username: SERVICE_ACCOUNT_USERNAME,
  password: loadPassword(),
});

function emit(event: Record<string, unknown>): void {
  const full = {
    ts: new Date().toISOString(),
    event_id: ulid(),
    service: "lldap-audit",
    ...event,
  };
  process.stdout.write(JSON.stringify(full) + "\n");
}

function actorIp(req: http.IncomingMessage): string {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) return xff.split(",")[0].trim();
  return req.socket.remoteAddress ?? "";
}

function actorFromRequest(req: http.IncomingMessage) {
  const auth = req.headers["authorization"];
  const authHeader = Array.isArray(auth) ? auth[0] : auth;
  const { claims, error } = decodeJwt(authHeader);
  const { userId, groups } = extractActor(claims);
  const uaRaw = req.headers["user-agent"] as unknown;
  let uaValue: string | null = null;
  if (typeof uaRaw === "string") uaValue = uaRaw;
  else if (Array.isArray(uaRaw)) uaValue = (uaRaw as string[]).join(",");
  return {
    user_id: userId,
    groups,
    ip: actorIp(req),
    user_agent: uaValue,
    ...(error ? { decode_error: error } : {}),
  };
}

async function readBody(req: http.IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}

async function forwardRaw(
  req: http.IncomingMessage,
  bodyBuf: Buffer,
): Promise<{ statusCode: number; headers: Record<string, string | string[]>; body: Buffer }> {
  const url = `${LLDAP_UPSTREAM}${req.url ?? "/"}`;
  const outHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue;
    if (k === "host" || k === "content-length" || k === "connection") continue;
    outHeaders[k] = Array.isArray(v) ? v.join(",") : v;
  }
  const res = await request(url, {
    method: req.method as any,
    headers: outHeaders,
    body: bodyBuf.length > 0 ? bodyBuf : undefined,
  });
  const respBuf = Buffer.from(await res.body.arrayBuffer());
  return {
    statusCode: res.statusCode,
    headers: res.headers as Record<string, string | string[]>,
    body: respBuf,
  };
}

interface GraphqlBody {
  operationName?: string;
  query?: string;
  variables?: Record<string, unknown>;
}

function parseGraphqlBody(buf: Buffer): GraphqlBody | null {
  if (buf.length === 0) return null;
  try {
    const parsed = JSON.parse(buf.toString("utf8"));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed as GraphqlBody;
    return null;
  } catch {
    return null;
  }
}

interface DiffEntry {
  field: string;
  from: unknown;
  to: unknown;
}

function computeDiff(
  before: Record<string, unknown> | null,
  after: Record<string, unknown> | null,
): DiffEntry[] {
  if (!before || !after) return [];
  const keys = new Set<string>([...Object.keys(before), ...Object.keys(after)]);
  const diff: DiffEntry[] = [];
  for (const k of keys) {
    const a = before[k];
    const b = after[k];
    if (JSON.stringify(a) !== JSON.stringify(b)) {
      diff.push({ field: k, from: a, to: b });
    }
  }
  return diff;
}

async function preImage(
  spec: MutationSpec,
  variables: Record<string, unknown>,
): Promise<{ image: Record<string, unknown> | null; error?: string }> {
  try {
    if (spec.targetKind === "user") {
      const id = resolvePath(variables, spec.idPath);
      if (!id) return { image: null };
      return { image: await lldap.fetchUser(id) };
    }
    if (spec.targetKind === "group") {
      const id = resolvePath(variables, spec.idPath);
      if (!id) return { image: null };
      return { image: await lldap.fetchGroup(id) };
    }
    return { image: null };
  } catch (e) {
    return { image: null, error: (e as Error).message };
  }
}

async function handleGraphql(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  bodyBuf: Buffer,
): Promise<void> {
  const start = Date.now();
  const actor = actorFromRequest(req);
  const parsed = parseGraphqlBody(bodyBuf);

  // Non-mutation or unparseable: forward verbatim, do not emit event.
  if (!parsed || (!looksLikeMutation(parsed.query) && !MUTATIONS[parsed.operationName ?? ""])) {
    const upstream = await forwardRaw(req, bodyBuf);
    writeResponse(res, upstream);
    return;
  }

  const opName = parsed.operationName ?? "unknown";
  const spec = MUTATIONS[opName];
  const variables = parsed.variables ?? {};
  const target = spec
    ? {
        kind: spec.targetKind,
        id: resolvePath(variables, spec.idPath),
        ...(spec.secondaryIdPath
          ? { secondary_id: resolvePath(variables, spec.secondaryIdPath) }
          : {}),
      }
    : { kind: "unknown", id: null };

  let before: Record<string, unknown> | null = null;
  let preImageError: string | undefined;
  if (spec?.needsPreImage) {
    const pre = await preImage(spec, variables);
    before = pre.image;
    preImageError = pre.error;
  }

  const upstream = await forwardRaw(req, bodyBuf);
  const durationMs = Date.now() - start;
  const httpStatus = upstream.statusCode;

  let responseJson: unknown = null;
  const contentType = String(upstream.headers["content-type"] ?? "");
  if (contentType.includes("application/json")) {
    try {
      responseJson = JSON.parse(upstream.body.toString("utf8"));
    } catch {
      responseJson = null;
    }
  }

  const gqlErrors =
    responseJson && typeof responseJson === "object" && "errors" in responseJson
      ? (responseJson as { errors?: unknown }).errors
      : null;

  const success = httpStatus < 400 && !gqlErrors;

  let after: Record<string, unknown> | null = null;
  let postImageError: string | undefined;
  if (success && spec?.needsPostImage) {
    try {
      const id = resolvePath(variables, spec.idPath);
      if (id) {
        if (spec.targetKind === "user") after = await lldap.fetchUser(id);
        else if (spec.targetKind === "group") after = await lldap.fetchGroup(id);
      }
    } catch (e) {
      postImageError = (e as Error).message;
    }
  }

  writeResponse(res, upstream);

  emit({
    event_type: spec?.eventType ?? "admin.unknown",
    operation: opName,
    actor: {
      user_id: actor.user_id,
      groups: actor.groups,
      ip: actor.ip,
      user_agent: actor.user_agent,
    },
    ...(actor.decode_error ? { actor_decode_error: actor.decode_error } : {}),
    target,
    request: { variables: redact(variables) },
    request_headers: redactHeaders(req.headers as Record<string, string | string[] | undefined>),
    before,
    after,
    diff: computeDiff(before, after),
    result: {
      status: success ? "success" : "error",
      http_status: httpStatus,
      duration_ms: durationMs,
      ...(gqlErrors ? { graphql_errors: gqlErrors } : {}),
    },
    ...(preImageError ? { pre_image_error: preImageError } : {}),
    ...(postImageError ? { post_image_error: postImageError } : {}),
  });
}

async function handleAuth(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  bodyBuf: Buffer,
): Promise<void> {
  const start = Date.now();
  const ip = actorIp(req);
  const ua = req.headers["user-agent"];
  let username: string | null = null;
  const url = req.url ?? "/";
  if (url.startsWith("/auth/simple/login")) {
    try {
      const parsed = JSON.parse(bodyBuf.toString("utf8"));
      if (parsed && typeof parsed === "object" && typeof parsed.username === "string") {
        username = parsed.username;
      }
    } catch {
      // ignore
    }
  }

  const upstream = await forwardRaw(req, bodyBuf);
  const durationMs = Date.now() - start;
  writeResponse(res, upstream);

  const success = upstream.statusCode >= 200 && upstream.statusCode < 300;
  emit({
    event_type: success ? "auth.login.success" : "auth.login.failure",
    operation: `HTTP ${req.method} ${url}`,
    actor: {
      user_id: username,
      groups: [],
      ip,
      user_agent: typeof ua === "string" ? ua : null,
    },
    target: { kind: "user", id: username },
    result: {
      status: success ? "success" : "error",
      http_status: upstream.statusCode,
      duration_ms: durationMs,
    },
  });
}

function writeResponse(
  res: http.ServerResponse,
  upstream: { statusCode: number; headers: Record<string, string | string[]>; body: Buffer },
): void {
  const outHeaders: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(upstream.headers)) {
    if (k.toLowerCase() === "content-length") continue;
    if (k.toLowerCase() === "transfer-encoding") continue;
    outHeaders[k] = v;
  }
  res.writeHead(upstream.statusCode, outHeaders);
  res.end(upstream.body);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = req.url ?? "/";
    const method = req.method ?? "GET";
    const bodyBuf = method === "GET" || method === "HEAD" ? Buffer.alloc(0) : await readBody(req);

    if (method === "POST" && url === "/api/graphql") {
      await handleGraphql(req, res, bodyBuf);
      return;
    }
    if (method === "POST" && url.startsWith("/auth/")) {
      await handleAuth(req, res, bodyBuf);
      return;
    }
    const upstream = await forwardRaw(req, bodyBuf);
    writeResponse(res, upstream);
  } catch (e) {
    emit({
      event_type: "audit.error",
      error: `handler-failure: ${(e as Error).message}`,
      stack: (e as Error).stack,
    });
    if (!res.headersSent) {
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "upstream-error" }));
    } else {
      res.end();
    }
  }
});

setInterval(() => {
  emit({ event_type: "audit.heartbeat" });
}, HEARTBEAT_INTERVAL_MS).unref();

emit({ event_type: "audit.start", upstream: LLDAP_UPSTREAM, port: PORT });

server.listen(PORT, "0.0.0.0", () => {
  emit({ event_type: "audit.listening", port: PORT });
});

function shutdown(signal: string): void {
  emit({ event_type: "audit.shutdown", signal });
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
