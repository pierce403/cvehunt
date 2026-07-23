/* CVEHunt's complete Pi tool surface for one isolated stage.
 * No process, shell, environment, or unrestricted network tool is exposed.
 */
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import dns from "node:dns";
import https from "node:https";
import net from "node:net";
import crypto from "node:crypto";
import { Type } from "@sinclair/typebox";

const MAX_READ = 2 * 1024 * 1024;
const MAX_FETCH = 5 * 1024 * 1024;
const MAX_WRITE = boundedIntegerEnv("CVEHUNT_STAGE_MAX_WRITE_BYTES", 8 * 1024 * 1024);

type ExtensionAPI = {
  registerTool(tool: {
    name: string;
    label: string;
    description: string;
    parameters: unknown;
    execute(id: string, args: any): Promise<any>;
  }): void;
};

function textResult(text: string, details: Record<string, unknown> = {}) {
  return { content: [{ type: "text", text }], details };
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`missing stage boundary ${name}`);
  return path.resolve(value);
}

function boundedIntegerEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  if (!/^[1-9][0-9]*$/.test(raw)) throw new Error(`invalid stage limit ${name}`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value > 1024 * 1024 * 1024) throw new Error(`invalid stage limit ${name}`);
  return value;
}

const roots = {
  input: requiredEnv("CVEHUNT_STAGE_INPUT"),
  workspace: requiredEnv("CVEHUNT_STAGE_WORKSPACE"),
  output: requiredEnv("CVEHUNT_STAGE_OUTPUT"),
};
const logRoot = requiredEnv("CVEHUNT_STAGE_LOG");

function lexicalPath(root: string, relative: string): string {
  if (!relative || path.isAbsolute(relative) || relative.includes("\0")) {
    throw new Error("path must be a non-empty relative path");
  }
  const normalized = path.normalize(relative);
  if (normalized === ".." || normalized.startsWith(`..${path.sep}`)) throw new Error("path traversal rejected");
  const result = path.resolve(root, normalized);
  if (result !== root && !result.startsWith(`${root}${path.sep}`)) throw new Error("path escapes stage root");
  return result;
}

async function rejectSymlinkComponents(root: string, target: string, allowMissingLeaf: boolean) {
  const relative = path.relative(root, target);
  let cursor = root;
  for (const component of relative.split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, component);
    try {
      const info = await fsp.lstat(cursor);
      if (info.isSymbolicLink()) throw new Error("symlink path rejected");
    } catch (error: any) {
      if (error?.code === "ENOENT" && allowMissingLeaf) return;
      throw error;
    }
  }
}

function selectedRoot(name: keyof typeof roots, write = false): string {
  if (write && name !== "workspace" && name !== "output") throw new Error("writes are limited to workspace/output");
  return roots[name];
}

async function confined(name: keyof typeof roots, relative: string, allowMissingLeaf = false, write = false) {
  const root = selectedRoot(name, write);
  const target = lexicalPath(root, relative);
  await rejectSymlinkComponents(root, target, allowMissingLeaf);
  return target;
}

function isForbiddenAddress(address: string): boolean {
  const lower = address.toLowerCase().split("%")[0];
  if (lower.startsWith("::ffff:")) return isForbiddenAddress(lower.slice(7));
  if (net.isIPv4(lower)) {
    const [a, b, c] = lower.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 0) ||
      (a === 192 && b === 168) || (a === 192 && b === 88) ||
      (a === 198 && (b === 18 || b === 19 || b === 51)) ||
      (a === 203 && b === 0) || (a === 192 && b === 0 && c === 2) || a >= 224;
  }
  if (net.isIPv6(lower)) {
    return lower === "::" || lower === "::1" || lower.startsWith("fc") || lower.startsWith("fd") ||
      /^fe[89ab]/.test(lower) || lower.startsWith("2001:db8:");
  }
  return true;
}

function normalizedHostname(value: string): string {
  const hostname = value.toLowerCase().replace(/\.$/, "");
  if (net.isIP(hostname) || hostname.length > 253 || !hostname.includes(".")) throw new Error("IP literals and invalid hostnames are rejected");
  if (!hostname.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new Error("invalid hostname");
  }
  return hostname;
}

function loadResearchHosts(): ReadonlySet<string> {
  if (process.env.CVEHUNT_STAGE_RESEARCH !== "1") return new Set();
  const policyPath = requiredEnv("CVEHUNT_STAGE_POLICY");
  const noFollow = (fs.constants as Record<string, number>).O_NOFOLLOW || 0;
  let descriptor: number;
  try {
    descriptor = fs.openSync(policyPath, fs.constants.O_RDONLY | noFollow);
  } catch {
    throw new Error("research policy is not an openable regular file");
  }
  let info: fs.Stats;
  let raw: string;
  try {
    info = fs.fstatSync(descriptor);
    if (!info.isFile() || info.uid !== 0 || info.nlink !== 1 || (info.mode & 0o022) !== 0) {
      throw new Error("research policy is not a root-owned, non-writable, single-link regular file");
    }
    if (info.size > 64 * 1024) throw new Error("research policy exceeds size limit");
    raw = fs.readFileSync(descriptor, "utf8");
  } finally {
    fs.closeSync(descriptor);
  }
  const policy = JSON.parse(raw);
  if (!policy || !Array.isArray(policy.research_hosts) || policy.research_hosts.length === 0) {
    throw new Error("research policy has no hostname allowlist");
  }
  const hosts = policy.research_hosts.map((host: unknown) => {
    if (typeof host !== "string" || host !== host.toLowerCase() || host.endsWith(".")) throw new Error("invalid research hostname policy");
    return normalizedHostname(host);
  });
  if (new Set(hosts).size !== hosts.length) throw new Error("duplicate research hostname policy");
  return new Set(hosts);
}

const researchHosts = loadResearchHosts();

async function resolveAllowedPublic(hostname: string): Promise<{ address: string; family: number }> {
  const host = normalizedHostname(hostname);
  if (!researchHosts.has(host)) throw new Error("hostname is outside the research policy");
  // Use A records only.  This intentionally fails closed for IPv6-only sources
  // rather than trying to maintain an incomplete translated/tunnel classifier.
  const addresses: string[] = await dns.promises.resolve4(host);
  const answers = addresses.map((address) => ({ address, family: 4 }));
  if (!answers.length || answers.some((answer) => isForbiddenAddress(answer.address))) {
    throw new Error("private, reserved, loopback, or unresolved destination rejected");
  }
  // Deterministic choice after validating every answer.  The request below pins
  // this exact address while preserving the hostname for Host and TLS SNI.
  return [...answers].sort((a, b) => a.address.localeCompare(b.address))[0];
}

function auditTarget(parsed: URL) {
  return {
    origin: parsed.origin,
    path_sha256: crypto.createHash("sha256").update(parsed.pathname).digest("hex"),
  };
}

async function logNetwork(parsed: URL, record: Record<string, unknown>) {
  const line = `${JSON.stringify({ timestamp: new Date().toISOString(), ...auditTarget(parsed), ...record })}\n`;
  await fsp.appendFile(path.join(logRoot, "network.ndjson"), line, { encoding: "utf8", mode: 0o600 });
}

async function retrieve(rawUrl: string): Promise<{ status: number; contentType: string; body: string }> {
  let parsed: URL;
  try { parsed = new URL(rawUrl); } catch { throw new Error("invalid URL"); }
  if (parsed.protocol !== "https:") throw new Error("only HTTPS retrieval is allowed");
  if (parsed.username || parsed.password) throw new Error("URL credentials rejected");
  for (const key of parsed.searchParams.keys()) {
    if (/(?:token|secret|passw|credential|api.?key|auth)/i.test(key)) {
      throw new Error("URL credential query rejected");
    }
  }
  if (parsed.port && parsed.port !== "443") throw new Error("non-standard HTTPS port rejected");
  const host = normalizedHostname(parsed.hostname);
  if (!researchHosts.has(host)) throw new Error("hostname is outside the research policy");
  const answer = await resolveAllowedPublic(host);
  const requestId = crypto.randomUUID();
  await logNetwork(parsed, { request_id: requestId, outcome: "started" });

  return await new Promise((resolve, reject) => {
    let settled = false;
    const finishReject = (error: Error) => {
      if (!settled) { settled = true; reject(error); }
    };
    const request = https.request({
      protocol: "https:", hostname: answer.address, port: 443,
      servername: host, path: `${parsed.pathname}${parsed.search}`, method: "GET",
      headers: { host, "user-agent": "CVEHunt-stage-research/1", accept: "text/*,application/json,application/xml" },
      timeout: 20_000,
    }, (response) => {
      const status = response.statusCode || 0;
      const type = String(response.headers["content-type"] || "");
      if (status >= 300 && status < 400) {
        response.resume();
        void logNetwork(parsed, { request_id: requestId, status, outcome: "redirect_rejected" }).finally(() => finishReject(new Error("redirects are rejected")));
        return;
      }
      if (status < 200 || status >= 300) {
        response.resume();
        void logNetwork(parsed, { request_id: requestId, status, outcome: "http_error" }).finally(() => finishReject(new Error(`HTTPS status ${status}`)));
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      response.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_FETCH) request.destroy(new Error("response exceeds retrieval limit"));
        else chunks.push(chunk);
      });
      response.on("end", () => {
        if (settled) return;
        const rawBody = Buffer.concat(chunks);
        const body = rawBody.toString("utf8");
        void logNetwork(parsed, {
          request_id: requestId, status, bytes: size,
          content_sha256: crypto.createHash("sha256").update(rawBody).digest("hex"),
          outcome: "completed",
        }).then(() => {
          if (!settled) { settled = true; resolve({ status, contentType: type, body }); }
        }, finishReject);
      });
    });
    request.on("timeout", () => request.destroy(new Error("HTTPS retrieval timed out")));
    request.on("error", (error) => {
      void logNetwork(parsed, { request_id: requestId, outcome: "error", error_type: error.name }).finally(() => finishReject(error));
    });
    request.end();
  });
}

export default function cvehuntStageTools(pi: ExtensionAPI) {
  pi.registerTool({
    name: "stage_read", label: "Read stage file",
    description: "Read a UTF-8 regular file copied into this stage or created in workspace/output. Links and traversal are rejected.",
    parameters: Type.Object({
      root: Type.Union([Type.Literal("input"), Type.Literal("workspace"), Type.Literal("output")]),
      path: Type.String(),
    }),
    async execute(_id, args) {
      const target = await confined(args.root, args.path);
      const info = await fsp.lstat(target);
      if (!info.isFile() || info.isSymbolicLink() || info.nlink > 1 || info.size > MAX_READ) {
        throw new Error("not a readable single-link regular stage file or file too large");
      }
      return textResult(await fsp.readFile(target, "utf8"), { root: args.root, path: args.path, bytes: info.size });
    },
  });

  pi.registerTool({
    name: "stage_list", label: "List stage directory",
    description: "List one stage-scoped directory. Links and special files make the operation fail closed.",
    parameters: Type.Object({
      root: Type.Union([Type.Literal("input"), Type.Literal("workspace"), Type.Literal("output")]),
      path: Type.Optional(Type.String({ default: "." })),
    }),
    async execute(_id, args) {
      const relative = args.path || ".";
      const target = relative === "." ? selectedRoot(args.root) : await confined(args.root, relative);
      const entries = await fsp.readdir(target, { withFileTypes: true });
      const visible = [];
      for (const entry of entries) {
        const info = await fsp.lstat(path.join(target, entry.name));
        if (info.isSymbolicLink() || (!info.isDirectory() && (!info.isFile() || info.nlink > 1))) {
          throw new Error("link or special directory entry rejected");
        }
        visible.push({ name: entry.name, type: info.isDirectory() ? "directory" : "file" });
      }
      return textResult(JSON.stringify(visible, null, 2), { count: visible.length });
    },
  });

  if (process.env.CVEHUNT_STAGE_AUTHORING === "1") {
    pi.registerTool({
      name: "stage_write", label: "Write stage file",
      description: `Create one UTF-8 file under workspace/output, at most ${MAX_WRITE} bytes. Links, overwrite, and traversal are rejected.`,
      parameters: Type.Object({
        root: Type.Union([Type.Literal("workspace"), Type.Literal("output")]),
        path: Type.String(), content: Type.String({ maxLength: MAX_WRITE }),
      }),
      async execute(_id, args) {
        const bytes = Buffer.byteLength(args.content, "utf8");
        if (bytes > MAX_WRITE) throw new Error("stage_write content exceeds configured byte limit");
        const target = await confined(args.root, args.path, true, true);
        await fsp.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
        await rejectSymlinkComponents(selectedRoot(args.root, true), target, true);
        const handle = await fsp.open(target, "wx", 0o600);
        try {
          const opened = await handle.stat();
          if (!opened.isFile() || opened.nlink !== 1) throw new Error("unsafe stage_write target");
          await handle.writeFile(args.content, "utf8");
        } finally { await handle.close(); }
        return textResult("written", { root: args.root, path: args.path, bytes });
      },
    });
  }

  if (process.env.CVEHUNT_STAGE_RESEARCH === "1") {
    pi.registerTool({
      name: "https_retrieve", label: "Retrieve allowlisted HTTPS source",
      description: "GET one policy-allowlisted public HTTPS hostname. Redirects, credentials, non-443 ports, and non-public DNS answers are rejected.",
      parameters: Type.Object({ url: Type.String() }),
      async execute(_id, args) {
        const result = await retrieve(args.url);
        return textResult(result.body, { status: result.status, contentType: result.contentType, bytes: Buffer.byteLength(result.body) });
      },
    });
  }
}
