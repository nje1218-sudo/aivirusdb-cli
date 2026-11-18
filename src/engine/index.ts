/**
 * @aivirusdb/scan-engine — pure, dependency-free static checks shared by the
 * AIVirusDB API (Cloudflare Worker) and the open-source CLI.
 *
 * The engine never reads files or makes network calls: callers pass contents.
 * It does not look packages up either; it returns them for the API to check
 * against the advisory database.
 */
import { excerpt, looksLikeSecretLiteral, redact } from "./redact.js";
import { PERMISSION_RULES } from "./rules/permissions.js";
import { TEXT_RULES } from "./rules/text.js";
import type { Finding, PackageRef, ScanReport, Severity, TargetKind, Verdict } from "./types.js";

export * from "./types.js";
export { redact } from "./redact.js";
export { PERMISSION_RULES, GITHUB_SCOPES_DOC } from "./rules/permissions.js";
export { TEXT_RULES } from "./rules/text.js";

export const RULES_VERSION = "2026-11-18.1";
const MAX_INPUT_BYTES = 1_000_000;

const SEVERITY_SCORE: Record<Severity, number> = { critical: 90, high: 70, medium: 40, low: 15 };

/**
 * Highest finding sets the score; each further finding adds 5, capped at 100.
 * Simple and explainable on purpose: the score must be reproducible from the findings.
 */
export function scoreFindings(findings: Finding[]): { risk_score: number; verdict: Verdict } {
  if (findings.length === 0) return { risk_score: 0, verdict: "no_known_issue" };
  const top = Math.max(...findings.map((f) => SEVERITY_SCORE[f.severity]));
  const risk_score = Math.min(100, top + 5 * (findings.length - 1));
  return { risk_score, verdict: risk_score >= 70 ? "high_risk" : "review" };
}

export async function fingerprint(text: string): Promise<string> {
  const normalized = text.replace(/\r\n?/g, "\n").replace(/^﻿/, "");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(normalized));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function guard(text: string): void {
  if (typeof text !== "string") throw new TypeError("input_must_be_text");
  if (new TextEncoder().encode(text).length > MAX_INPUT_BYTES) throw new RangeError("input_too_large");
}

async function report(kind: TargetKind, input: string, findings: Finding[], packages: PackageRef[] = []): Promise<ScanReport> {
  return {
    schema_version: "aivdb-scan-v1",
    rules_version: RULES_VERSION,
    target_kind: kind,
    fingerprint_sha256: await fingerprint(input),
    ...scoreFindings(findings),
    findings,
    packages,
  };
}

/** Scan an Agent Skill file, project rule file, prompt template or workflow script. */
export async function scanSkillFile(path: string, content: string): Promise<ScanReport> {
  guard(content);
  const findings: Finding[] = [];
  const lines = content.split(/\r\n?|\n/);
  for (const rule of TEXT_RULES) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      if (rule.patterns.some((p) => p.test(line))) {
        findings.push({
          rule_id: rule.id, severity: rule.severity, title: rule.title, detail: rule.detail,
          location: path, line: i + 1, excerpt: excerpt(line), owasp_asi: rule.owasp_asi, references: [],
        });
        break; // one finding per rule per file keeps reports readable
      }
    }
  }
  return report("skill_file", content, findings);
}

interface McpServerEntry {
  command?: unknown;
  args?: unknown;
  env?: unknown;
  url?: unknown;
}

const NPM_RUNNERS = new Set(["npx", "bunx", "pnpx"]);
const PY_RUNNERS = new Set(["uvx", "pipx"]);

function parseNpmSpec(spec: string): { name: string; version?: string } {
  const at = spec.startsWith("@") ? spec.indexOf("@", 1) : spec.indexOf("@");
  if (at <= 0) return { name: spec };
  const version = spec.slice(at + 1);
  return { name: spec.slice(0, at), version: version && version !== "latest" ? version : undefined };
}

function parsePySpec(spec: string): { name: string; version?: string } {
  const match = /^([A-Za-z0-9._-]+)(?:==([A-Za-z0-9._+-]+))?$/.exec(spec);
  return match ? { name: match[1] ?? spec, version: match[2] } : { name: spec };
}

function firstPackageArg(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? "";
    if (arg === "--from" || arg === "-p" || arg === "--package") return args[i + 1];
    if (!arg.startsWith("-")) return arg;
  }
  return undefined;
}

/**
 * Scan an MCP client config (the `mcpServers` / `servers` object used by
 * Claude Desktop, Cursor, VS Code and similar clients).
 */
export async function scanMcpConfig(path: string, content: string): Promise<ScanReport> {
  guard(content);
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new SyntaxError("mcp_config_not_json");
  }
  const root = (parsed ?? {}) as Record<string, unknown>;
  const servers = (root.mcpServers ?? root.servers ?? {}) as Record<string, McpServerEntry>;
  if (typeof servers !== "object" || Array.isArray(servers)) throw new SyntaxError("mcp_config_shape_invalid");

  const findings: Finding[] = [];
  const packages: PackageRef[] = [];
  for (const [name, server] of Object.entries(servers)) {
    if (!server || typeof server !== "object") continue;
    const where = `${path}#${name}`;
    const command = typeof server.command === "string" ? server.command.trim() : "";
    const args = Array.isArray(server.args) ? server.args.filter((a): a is string => typeof a === "string") : [];
    const base = command.split(/[\\/]/).pop() ?? command;

    if (NPM_RUNNERS.has(base) || PY_RUNNERS.has(base)) {
      const spec = firstPackageArg(args);
      if (spec) {
        const ecosystem = NPM_RUNNERS.has(base) ? "npm" : "pypi";
        const { name: pkg, version } = ecosystem === "npm" ? parseNpmSpec(spec) : parsePySpec(spec);
        packages.push({ ecosystem, name: pkg, version, source: where });
        if (!version) {
          findings.push({
            rule_id: "MCP001", severity: "medium", title: "MCP server package is not pinned",
            detail: `\`${pkg}\` is started without an exact version, so every launch can pull a new release. ` +
              "An unpinned server can change behaviour after you approved it (rug pull).",
            location: where, excerpt: excerpt(`${command} ${args.join(" ")}`),
            owasp_asi: ["ASI04"], references: [],
          });
        }
      }
    } else if (base === "docker" && args.includes("run")) {
      const image = args.slice(args.indexOf("run") + 1).find((a) => !a.startsWith("-") && !a.includes("="));
      if (image) {
        const [repo, tag] = image.split("@")[0]?.split(":") ?? [image];
        packages.push({ ecosystem: "docker", name: repo ?? image, version: image.includes("@sha256:") ? image.split("@")[1] : tag, source: where });
      }
    }

    if (["sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"].includes(base) && args.some((a) => /^-(?:c|Command|command)$|^\/c$/.test(a))) {
      findings.push({
        rule_id: "MCP004", severity: "high", title: "MCP server is an inline shell command",
        detail: "The server runs an arbitrary shell command line instead of a named package, so nothing can be checked against advisories and the command itself must be reviewed.",
        location: where, excerpt: excerpt(`${command} ${args.join(" ")}`), owasp_asi: ["ASI04", "ASI05"], references: [],
      });
    }

    if (typeof server.url === "string" && /^http:\/\//i.test(server.url) && !/^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i.test(server.url)) {
      findings.push({
        rule_id: "MCP003", severity: "high", title: "Remote MCP server over plain HTTP",
        detail: "Tool calls and results travel unencrypted, so anyone on the path can read or alter them.",
        location: where, excerpt: excerpt(server.url), owasp_asi: ["ASI07"], references: [],
      });
    }

    if (server.env && typeof server.env === "object") {
      const literal = Object.entries(server.env as Record<string, unknown>)
        .filter(([, v]) => typeof v === "string" && looksLikeSecretLiteral(v))
        .map(([k]) => k);
      if (literal.length > 0) {
        findings.push({
          rule_id: "MCP002", severity: "high", title: "Credentials written inline in the MCP config",
          detail: `Literal secret values are set for ${literal.join(", ")}. Every agent and tool that can read this file inherits them, ` +
            "and the file is easy to commit by mistake. Reference an environment variable or secret store instead.",
          location: where, owasp_asi: ["ASI03"], references: [],
        });
      }
    }
  }
  return report("mcp_config", content, findings, packages);
}

/** Score a set of scopes granted to an agent for one provider. */
export async function scanPermissions(provider: string, scopes: string[], location = provider): Promise<ScanReport> {
  if (!Array.isArray(scopes) || scopes.some((s) => typeof s !== "string")) throw new TypeError("scopes_must_be_strings");
  const granted = new Set(scopes.map((s) => s.trim().toLowerCase()));
  const matched = PERMISSION_RULES.filter((r) => r.provider === provider && r.requires_all.every((s) => granted.has(s)));
  // A broader rule (more required scopes) explains the narrower one it contains; keep only the most specific.
  const specific = matched.filter((rule) => !matched.some((other) =>
    other !== rule && other.requires_all.length > rule.requires_all.length
    && rule.requires_all.every((s) => other.requires_all.includes(s))));
  const findings: Finding[] = specific.map((r) => ({
    rule_id: r.id, severity: r.severity, title: r.title, detail: r.detail, location,
    excerpt: redact(r.requires_all.join(" + ")), owasp_asi: r.owasp_asi, references: r.references,
  }));
  return report("permission_set", `${provider}\n${[...granted].sort().join("\n")}`, findings);
}
