#!/usr/bin/env node
/**
 * aivirusdb scan [dir] [--json] [--fail-on <severity>] [--github-scopes a,b]
 *
 * Exit codes: 0 = nothing at or above the threshold, 1 = issues at or above
 * the threshold, 2 = usage or runtime error.
 */
import { resolve } from "node:path";
import { stat } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { formatText } from "./format.js";
import { exceedsThreshold, scanProject } from "./scan.js";
import type { Fetch } from "./api.js";

const USAGE = `Usage: aivirusdb scan [dir] [options]

Scans MCP configs (mcp.json, .mcp.json, claude_desktop_config.json, ...),
Agent Skill and rule files (SKILL.md, .cursorrules, .cursor/rules/*.mdc,
AGENTS.md, CLAUDE.md, ...) and, optionally, a GitHub permission set.

Options:
  --json                 Print machine-readable JSON
  --fail-on <level>      critical | high | medium | low | none (default: high)
  --github-scopes <list> Comma-separated GitHub OAuth scopes the agent holds
  --api-url <url>        Override the advisory API endpoint
  -h, --help             Show this help

Set AIVIRUSDB_API_KEY to also check MCP packages against known advisories.
Only package names and versions are sent; file contents stay on this machine.`;

export interface Io { out: (s: string) => void; err: (s: string) => void; env: Record<string, string | undefined>; fetch?: Fetch }

const LEVELS = new Set(["critical", "high", "medium", "low", "none"]);

export async function main(argv: string[], io: Io): Promise<number> {
  const args = [...argv];
  if (args[0] === "-h" || args[0] === "--help" || args.length === 0) { io.out(USAGE); return args.length === 0 ? 2 : 0; }
  if (args.shift() !== "scan") { io.err(USAGE); return 2; }
  let dir = ".", json = false, failOn = "high", scopes: string[] | undefined, apiUrl: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    const value = () => { const v = args[++i]; if (v === undefined) throw new Error(`missing value for ${arg}`); return v; };
    try {
      if (arg === "--json") json = true;
      else if (arg === "--fail-on") failOn = value();
      else if (arg === "--github-scopes") scopes = value().split(",").map(s => s.trim()).filter(Boolean);
      else if (arg === "--api-url") apiUrl = value();
      else if (arg === "-h" || arg === "--help") { io.out(USAGE); return 0; }
      else if (arg.startsWith("-")) { io.err(`unknown option ${arg}\n\n${USAGE}`); return 2; }
      else dir = arg;
    } catch (e) { io.err((e as Error).message); return 2; }
  }
  if (!LEVELS.has(failOn)) { io.err(`--fail-on must be one of ${[...LEVELS].join(", ")}`); return 2; }
  const root = resolve(dir);
  try {
    if (!(await stat(root)).isDirectory()) throw new Error();
  } catch { io.err(`not a directory: ${dir}`); return 2; }
  try {
    const scan = await scanProject({ root, githubScopes: scopes, apiKey: io.env.AIVIRUSDB_API_KEY, apiUrl, fetch: io.fetch });
    io.out(json ? JSON.stringify(scan, null, 2) : formatText(scan));
    return exceedsThreshold(scan, failOn as never) ? 1 : 0;
  } catch (e) {
    io.err(`scan failed: ${e instanceof Error ? e.message : "unknown_error"}`);
    return 2;
  }
}

function invokedDirectly(): boolean {
  // npm/npx run bins through a symlink, so compare real paths.
  try { return import.meta.url === pathToFileURL(realpathSync(process.argv[1] ?? "")).href; } catch { return false; }
}

if (invokedDirectly()) {
  main(process.argv.slice(2), { out: s => console.log(s), err: s => console.error(s), env: process.env })
    .then(code => { process.exitCode = code; });
}
