/**
 * GitHub Actions output: workflow-command annotations (shown inline on the PR
 * diff) and a Markdown job summary.
 */
import type { ProjectScan } from "./scan.js";
import type { Severity } from "./engine/index.js";

// https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands
function escapeData(value: string): string {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
function escapeProperty(value: string): string {
  return escapeData(value).replace(/:/g, "%3A").replace(/,/g, "%2C");
}

const LEVEL: Record<Severity, "error" | "warning" | "notice"> = {
  critical: "error", high: "error", medium: "warning", low: "notice",
};

/** One workflow command per finding. File paths are relative to the scanned root. */
export function annotations(scan: ProjectScan, pathPrefix = ""): string[] {
  const out: string[] = [];
  for (const report of scan.reports) {
    for (const f of report.findings) {
      const props: string[] = [`title=${escapeProperty(`${f.rule_id} ${f.title}`)}`];
      if (report.target_kind !== "permission_set") {
        const file = f.location.split("#")[0] ?? f.location;
        props.unshift(`file=${escapeProperty(pathPrefix + file)}`);
        if (f.line) props.splice(1, 0, `line=${f.line}`);
      }
      const message = f.excerpt ? `${f.detail}\n> ${f.excerpt}` : f.detail;
      out.push(`::${LEVEL[f.severity]} ${props.join(",")}::${escapeData(message)}`);
    }
  }
  if (scan.advisories.status === "checked") {
    for (const p of scan.advisories.result.packages) {
      if (p.verdict !== "affected") continue;
      const source = p.package.source?.split("#")[0];
      for (const m of p.matches) {
        const props = [`title=${escapeProperty(`${m.advisory_ids[0] ?? m.id} ${p.package.name}@${p.package.version ?? "?"}`)}`];
        if (source && source !== "request") props.unshift(`file=${escapeProperty(pathPrefix + source)}`);
        out.push(`::error ${props.join(",")}::${escapeData(`${m.title ?? "Known advisory"}${m.evidence_url ? `\n${m.evidence_url}` : ""}`)}`);
      }
    }
  }
  return out;
}

function cell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

export function summaryMarkdown(scan: ProjectScan, failed: boolean, failOn: string): string {
  const rows: string[] = [];
  for (const report of scan.reports) {
    for (const f of report.findings) {
      const where = f.line ? `${f.location}:${f.line}` : f.location;
      rows.push(`| ${f.severity} | \`${f.rule_id}\` | ${cell(f.title)} | \`${cell(where)}\` |`);
    }
  }
  if (scan.advisories.status === "checked") {
    for (const p of scan.advisories.result.packages.filter(x => x.verdict === "affected")) {
      for (const m of p.matches) {
        const link = m.evidence_url ? `[${cell(m.advisory_ids[0] ?? m.id)}](${m.evidence_url})` : cell(m.advisory_ids[0] ?? m.id);
        rows.push(`| ${m.severity ?? "high"} | ${link} | ${cell(m.title ?? "Known advisory")} | \`${cell(`${p.package.name}@${p.package.version ?? "?"}`)}\` |`);
      }
    }
  }
  const files = scan.reports.filter(r => r.target_kind !== "permission_set").length;
  const lines = [
    `## AIVirusDB scan ${failed ? "❌" : "✅"}`,
    "",
    `Rules \`${scan.rules_version}\` · ${files} file(s) checked · fail on \`${failOn}\``,
    "",
  ];
  if (rows.length) lines.push("| Severity | Rule | Finding | Where |", "|---|---|---|---|", ...rows, "");
  else lines.push("No known issues found. This means no rule or advisory matched; it is not a guarantee of safety.", "");
  if (scan.advisories.status === "skipped" && scan.advisories.reason === "no_api_key") {
    lines.push("Known-advisory lookup was skipped. Set an `api-key` to check MCP packages against known advisories.", "");
  } else if (scan.advisories.status === "skipped" && scan.advisories.reason !== "no_packages") {
    lines.push(`Known-advisory lookup was skipped: \`${scan.advisories.reason}\`.`, "");
  }
  return lines.join("\n");
}
