/**
 * Find the agent configuration files in a project directory.
 *
 * Only well-known file names are read. Nothing is followed outside the
 * project root (symlinks are skipped) and large files are ignored.
 */
import { lstat, readdir, readFile } from "node:fs/promises";
import { join, relative, sep } from "node:path";

export type FileKind = "mcp_config" | "skill_file";

export interface FoundFile {
  /** Path relative to the scanned root, with forward slashes. */
  path: string;
  kind: FileKind;
  content: string;
}

const MAX_FILE_BYTES = 1_000_000;
const MAX_FILES = 500;
const MAX_DEPTH = 12;
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", ".venv", "venv", "__pycache__", "vendor", "target"]);

const MCP_NAMES = new Set(["mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json"]);
const RULE_NAMES = new Set([
  "SKILL.md", ".cursorrules", ".windsurfrules", ".clinerules", "AGENTS.md", "CLAUDE.md", "GEMINI.md",
  "copilot-instructions.md",
]);

/** Classify a relative path, or return null when the file is not an agent config. */
export function classify(relPath: string): FileKind | null {
  const parts = relPath.split("/");
  const name = parts[parts.length - 1] ?? "";
  if (MCP_NAMES.has(name)) return "mcp_config";
  if (RULE_NAMES.has(name)) return "skill_file";
  const dir = parts.slice(0, -1).join("/");
  if (/(^|\/)\.cursor\/rules$/.test(dir) && /\.(mdc|md)$/.test(name)) return "skill_file";
  if (/(^|\/)\.claude\/(commands|agents)$/.test(dir) && name.endsWith(".md")) return "skill_file";
  if (/(^|\/)\.github\/prompts$/.test(dir) && name.endsWith(".prompt.md")) return "skill_file";
  return null;
}

export interface DiscoverResult { files: FoundFile[]; skipped: { path: string; reason: string }[] }

export async function discover(root: string): Promise<DiscoverResult> {
  const files: FoundFile[] = [];
  const skipped: { path: string; reason: string }[] = [];

  async function walk(dir: string, depth: number): Promise<void> {
    if (depth > MAX_DEPTH || files.length >= MAX_FILES) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const full = join(dir, entry.name);
      const rel = relative(root, full).split(sep).join("/");
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) await walk(full, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      const kind = classify(rel);
      if (!kind) continue;
      const info = await lstat(full);
      if (info.size > MAX_FILE_BYTES) {
        skipped.push({ path: rel, reason: "file_too_large" });
        continue;
      }
      files.push({ path: rel, kind, content: await readFile(full, "utf8") });
    }
  }

  await walk(root, 0);
  return { files, skipped };
}
