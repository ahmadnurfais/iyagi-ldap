import http from "node:http";
import fs from "node:fs";
import { ulid } from "ulid";
import { request } from "undici";
import { verifyJwt, extractActor } from "./jwt.js";
import { redact, redactHeaders } from "./redact.js";
import { LldapClient } from "./lldap-client.js";
import { MUTATIONS, looksLikeMutation, resolvePath, type MutationSpec } from "./mutations.js";

const PORT = Number(process.env.PORT ?? 8080);
const LLDAP_UPSTREAM = process.env.LLDAP_UPSTREAM ?? "http://lldap:17170";
const SERVICE_ACCOUNT_USERNAME = process.env.SERVICE_ACCOUNT_USERNAME ?? "iyagi_audit_interceptor";
const SERVICE_ACCOUNT_PASSWORD_FILE =
  process.env.SERVICE_ACCOUNT_PASSWORD_FILE ?? "/run/secrets/audit-interceptor-password";
const JWT_SECRET_FILE = process.env.JWT_SECRET_FILE ?? "/run/secrets/lldap-jwt-secret";
const HEARTBEAT_INTERVAL_MS = Number(process.env.HEARTBEAT_INTERVAL_MS ?? 60_000);
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES ?? 1_048_576);
const UPSTREAM_TIMEOUT_MS = Number(process.env.UPSTREAM_TIMEOUT_MS ?? 30_000);

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
const jwtSecret = fs.readFileSync(JWT_SECRET_FILE, "utf8").trim();

function emit(event: Record<string, unknown>): void {
  const actor = event.actor as Record<string, unknown> | undefined;
  const target = event.target as Record<string, unknown> | undefined;
  const result = event.result as Record<string, unknown> | undefined;
  const diff = Array.isArray(event.diff) ? (event.diff as DiffEntry[]) : [];
  const full = {
    ts: new Date().toISOString(),
    event_id: ulid(),
    service: "lldap-audit",
    ...event,
    actor_user_id: typeof actor?.user_id === "string" ? actor.user_id : null,
    actor_ip: typeof actor?.ip === "string" ? actor.ip : null,
    actor_user_agent: typeof actor?.user_agent === "string" ? actor.user_agent : null,
    actor_verified: actor?.identity_verified === true,
    target_kind: typeof target?.kind === "string" ? target.kind : null,
    target_id:
      typeof target?.id === "string" || typeof target?.id === "number"
        ? String(target.id)
        : null,
    target_name: typeof target?.name === "string" ? target.name : null,
    target_email: typeof target?.email === "string" ? target.email : null,
    target_secondary_id:
      typeof target?.secondary_id === "string" || typeof target?.secondary_id === "number"
        ? String(target.secondary_id)
        : null,
    target_secondary_name:
      typeof target?.secondary_name === "string" ? target.secondary_name : null,
    result_status: typeof result?.status === "string" ? result.status : null,
    result_http_status: typeof result?.http_status === "number" ? result.http_status : null,
    result_duration_ms: typeof result?.duration_ms === "number" ? result.duration_ms : null,
    changed_fields: diff.map((entry) => entry.field),
    change_summary: diff
      .map((entry) => `${entry.field}: ${JSON.stringify(entry.from)} -> ${JSON.stringify(entry.to)}`)
      .join("; "),
  };
  process.stdout.write(JSON.stringify(full) + "\n");
}

function actorIp(req: http.IncomingMessage): string {
  const realIp = req.headers["x-real-ip"];
  if (typeof realIp === "string" && realIp.length > 0) return realIp.trim();
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) return xff.split(",")[0].trim();
  return req.socket.remoteAddress ?? "";
}

function actorFromRequest(req: http.IncomingMessage) {
  const auth = req.headers["authorization"];
  let authHeader = Array.isArray(auth) ? auth[0] : auth;
  if (!authHeader) {
    const cookie = req.headers.cookie;
    const token = cookie
      ?.split(";")
      .map((part) => part.trim())
      .find((part) => part.startsWith("token="))
      ?.slice("token=".length);
    if (token) authHeader = `Bearer ${token}`;
  }
  const { claims, verified, error } = verifyJwt(authHeader, jwtSecret);
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
    identity_verified: verified,
    ...(error ? { decode_error: error } : {}),
  };
}

async function readBody(req: http.IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new Error("request-body-too-large");
    chunks.push(chunk as Buffer);
  }
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
    headersTimeout: UPSTREAM_TIMEOUT_MS,
    bodyTimeout: UPSTREAM_TIMEOUT_MS,
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

function actionSummary(
  eventType: string,
  actorId: string | null,
  target: {
    kind: string;
    id: string | null;
    name?: string | null;
    email?: string | null;
    secondary_id?: string | null;
    secondary_name?: string | null;
  },
): string {
  const actor = actorId ?? "Unknown administrator";
  const rawTargetId = target.name ?? target.id ?? "unknown target";
  const targetId = target.email ? `${rawTargetId} (${target.email})` : rawTargetId;
  const group = target.secondary_name ?? target.secondary_id ?? "unknown group";
  switch (eventType) {
    case "admin.group.member.add":
      return `${actor} added ${targetId} to ${group}`;
    case "admin.group.member.remove":
      return `${actor} removed ${targetId} from ${group}`;
    case "admin.user.create":
      return `${actor} created user ${targetId}`;
    case "admin.user.update":
      return `${actor} updated user ${targetId}`;
    case "admin.user.delete":
      return `${actor} deleted user ${targetId}`;
    case "admin.group.create":
      return `${actor} created group ${targetId}`;
    case "admin.group.update":
      return `${actor} updated group ${targetId}`;
    case "admin.group.delete":
      return `${actor} deleted group ${targetId}`;
    case "admin.user.password-change":
      return `${actor} changed the password for ${targetId}`;
    default:
      return `${actor} performed ${eventType} on ${targetId}`;
  }
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
  const target: {
    kind: string;
    id: string | null;
    name?: string | null;
    email?: string | null;
    secondary_id?: string | null;
    secondary_name?: string | null;
  } = spec
    ? {
        kind: spec.targetKind,
        id: resolvePath(variables, spec.idPath),
        ...(spec.secondaryIdPath
          ? { secondary_id: resolvePath(variables, spec.secondaryIdPath) }
          : {}),
      }
    : { kind: "unknown", id: null };

  let targetProfileError: string | undefined;
  if (spec?.targetKind === "membership" && target.secondary_id) {
    try {
      const group = await lldap.fetchGroup(target.secondary_id);
      const displayName = group?.displayName;
      if (typeof displayName === "string") target.secondary_name = displayName;
    } catch (e) {
      targetProfileError = (e as Error).message;
    }
  }
  if (spec?.targetKind === "membership" && target.id) {
    try {
      const user = await lldap.fetchUser(target.id);
      if (typeof user?.email === "string" && user.email.length > 0) target.email = user.email;
    } catch (e) {
      targetProfileError = (e as Error).message;
    }
  }

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

  if (spec?.targetKind === "group") {
    const groupName = after?.displayName ?? before?.displayName;
    if (typeof groupName === "string") target.name = groupName;
  }
  if (spec?.targetKind === "user") {
    const targetEmail = after?.email ?? before?.email;
    if (typeof targetEmail === "string" && targetEmail.length > 0) target.email = targetEmail;
  }

  writeResponse(res, upstream);

  const eventType = spec?.eventType ?? "admin.unknown";
  const redactedBefore = redact(before) as Record<string, unknown> | null;
  const redactedAfter = redact(after) as Record<string, unknown> | null;
  emit({
    event_type: eventType,
    action_summary: actionSummary(eventType, actor.user_id, target),
    operation: opName,
    actor: {
      user_id: actor.user_id,
      groups: actor.groups,
      ip: actor.ip,
     user_agent: actor.user_agent,
      identity_verified: actor.identity_verified,
    },
    ...(actor.decode_error ? { actor_decode_error: actor.decode_error } : {}),
    target,
    request: { variables: redact(variables) },
    request_headers: redactHeaders({
      "content-type": req.headers["content-type"],
      "user-agent": req.headers["user-agent"],
      "x-forwarded-for": req.headers["x-forwarded-for"],
      "x-forwarded-host": req.headers["x-forwarded-host"],
      "x-forwarded-proto": req.headers["x-forwarded-proto"],
    }),
    before: redactedBefore,
    after: redactedAfter,
    diff: computeDiff(redactedBefore, redactedAfter),
    result: {
      status: success ? "success" : "error",
      http_status: httpStatus,
      duration_ms: durationMs,
      ...(gqlErrors ? { graphql_errors: gqlErrors } : {}),
    },
    ...(preImageError ? { pre_image_error: preImageError } : {}),
    ...(postImageError ? { post_image_error: postImageError } : {}),
    ...(targetProfileError ? { target_profile_error: targetProfileError } : {}),
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
  if (url.startsWith("/auth/simple/login") || url.includes("/login/start") || url.includes("/register/start")) {
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
  let eventType = "auth.request";
  if (url === "/auth/simple/login" || url.includes("/login/finish")) {
    eventType = success ? "auth.login.success" : "auth.login.failure";
  } else if (url.includes("/login/start")) {
    eventType = success ? "auth.login.start" : "auth.login.failure";
  } else if (url.includes("/register/")) {
    eventType = success ? "admin.user.password-change" : "admin.user.password-change.failure";
  } else if (url.includes("/reset/")) {
    eventType = success ? "auth.password-reset" : "auth.password-reset.failure";
  } else if (url.includes("/logout")) {
    eventType = success ? "auth.logout" : "auth.logout.failure";
  } else if (url.includes("/refresh")) {
    eventType = success ? "auth.token.refresh" : "auth.token.refresh.failure";
  }
  const requestActor = actorFromRequest(req);
  emit({
    event_type: eventType,
    operation: `HTTP ${req.method} ${url}`,
    actor: {
      user_id: requestActor.user_id ?? username,
      groups: requestActor.groups,
      ip,
      user_agent: typeof ua === "string" ? ua : null,
      identity_verified: requestActor.identity_verified,
    },
    target: { kind: "user", id: username ?? requestActor.user_id },
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
    if (
      url.startsWith("/auth/") &&
      (method !== "GET" || url.startsWith("/auth/refresh") || url.startsWith("/auth/logout"))
    ) {
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
      const tooLarge = (e as Error).message === "request-body-too-large";
      res.writeHead(tooLarge ? 413 : 502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: tooLarge ? "request-body-too-large" : "upstream-error" }));
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
