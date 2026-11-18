/** Human-readable report. Machine output is the JSON from scanProject. */
import type { ProjectScan } from "./scan.js";

const ICON: Record<string, string> = { critical: "✖", high: "✖", medium: "!", low: "·" };

export function formatText(scan: ProjectScan): string {
  const lines: string[] = [];
  const files = scan.reports.filter(r => r.target_kind !== "permission_set");
  lines.push(`AIVirusDB scan · rules ${scan.rules_version} · ${files.length} file(s) checked`);
  let total = 0;
  for (const report of scan.reports) {
    for (const f of report.findings) {
      total++;
      const where = f.line ? `${f.location}:${f.line}` : f.location;
      lines.push(`${ICON[f.severity] ?? "-"} ${f.severity.toUpperCase().padEnd(8)} ${f.rule_id.padEnd(11)} ${where}`);
      lines.push(`    ${f.title}`);
      if (f.excerpt) lines.push(`    > ${f.excerpt}`);
    }
  }
  if (scan.advisories.status === "checked") {
    for (const p of scan.advisories.result.packages) {
      const name = `${p.package.name}${p.package.version ? `@${p.package.version}` : ""}`;
      if (p.verdict === "affected") {
        total++;
        for (const m of p.matches) {
          lines.push(`✖ ADVISORY ${(m.advisory_ids[0] ?? m.id).padEnd(20)} ${name}`);
          if (m.title) lines.push(`    ${m.title}`);
          if (m.evidence_url) lines.push(`    ${m.evidence_url}`);
        }
      } else if (p.verdict === "unknown") {
        lines.push(`? UNKNOWN  ${name} (${p.reason ?? "cannot_evaluate"})`);
      }
    }
    const usage = scan.advisories.result.usage;
    if (usage) lines.push(`Advisory lookups this month: ${usage.calls}/${usage.quota}`);
  } else if (scan.advisories.reason === "no_api_key") {
    lines.push("Advisory lookup skipped: set AIVIRUSDB_API_KEY to check MCP packages against known advisories.");
  } else if (scan.advisories.reason !== "no_packages") {
    lines.push(`Advisory lookup skipped: ${scan.advisories.reason}`);
  }
  for (const e of scan.errors) lines.push(`! could not scan ${e.path}: ${e.error}`);
  for (const s of scan.skipped) lines.push(`· skipped ${s.path}: ${s.reason}`);
  lines.push(total === 0
    ? "No known issues found. This means no rule or advisory matched; it is not a guarantee of safety."
    : `${total} issue(s) found.`);
  return lines.join("\n");
}
