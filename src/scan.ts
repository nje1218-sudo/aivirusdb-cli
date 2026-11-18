/** Run every local check for a project and combine the results. */
import { lookupPackages, type Fetch, type LookupResult } from "./api.js";
import { discover } from "./discover.js";
import { scanMcpConfig, scanPermissions, scanSkillFile, RULES_VERSION, type ScanReport, type Severity } from "./engine/index.js";

export interface ScanOptions {
  root: string;
  githubScopes?: string[];
  apiKey?: string;
  apiUrl?: string;
  fetch?: Fetch;
}

export interface ProjectScan {
  schema_version: "aivdb-cli-scan-v1";
  rules_version: string;
  root: string;
  reports: ScanReport[];
  errors: { path: string; error: string }[];
  skipped: { path: string; reason: string }[];
  /** Advisory lookup result, or why it did not run. */
  advisories: { status: "checked"; result: LookupResult } | { status: "skipped"; reason: string };
}

export async function scanProject(options: ScanOptions): Promise<ProjectScan> {
  const { files, skipped } = await discover(options.root);
  const reports: ScanReport[] = [];
  const errors: { path: string; error: string }[] = [];
  for (const file of files) {
    try {
      reports.push(file.kind === "mcp_config" ? await scanMcpConfig(file.path, file.content) : await scanSkillFile(file.path, file.content));
    } catch (e) {
      errors.push({ path: file.path, error: e instanceof Error ? e.message : "scan_failed" });
    }
  }
  if (options.githubScopes && options.githubScopes.length > 0) {
    reports.push(await scanPermissions("github", options.githubScopes, "--github-scopes"));
  }
  const packages = reports.flatMap(r => r.packages);
  let advisories: ProjectScan["advisories"];
  if (!options.apiKey) advisories = { status: "skipped", reason: packages.length ? "no_api_key" : "no_packages" };
  else if (packages.length === 0) advisories = { status: "skipped", reason: "no_packages" };
  else {
    try {
      advisories = { status: "checked", result: await lookupPackages(packages, { apiKey: options.apiKey, apiUrl: options.apiUrl, fetch: options.fetch }) };
    } catch (e) {
      advisories = { status: "skipped", reason: e instanceof Error ? e.message : "api_failed" };
    }
  }
  return { schema_version: "aivdb-cli-scan-v1", rules_version: RULES_VERSION, root: options.root, reports, errors, skipped, advisories };
}

const RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

/** True when any finding (or affected package) is at or above the threshold. */
export function exceedsThreshold(scan: ProjectScan, failOn: Severity | "none"): boolean {
  if (failOn === "none") return false;
  const limit = RANK[failOn];
  const findings = scan.reports.some(r => r.findings.some(f => RANK[f.severity] >= limit));
  const affected = scan.advisories.status === "checked" && scan.advisories.result.packages.some(p => p.verdict === "affected"
    && p.matches.some(m => (m.severity && m.severity in RANK ? RANK[m.severity as Severity] : RANK.high) >= limit));
  return findings || affected;
}
