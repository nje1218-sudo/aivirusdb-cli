/** Shared result types for every check (MCP config, skill/rule files, permissions). */

export type Severity = "critical" | "high" | "medium" | "low";

export type TargetKind = "mcp_config" | "skill_file" | "permission_set";

export interface Finding {
  /** Stable rule id, e.g. "SKL001". Never reused for a different meaning. */
  rule_id: string;
  severity: Severity;
  title: string;
  /** What was found and why it matters, in plain language. */
  detail: string;
  /** Where it was found: file path, MCP server name or permission provider. */
  location: string;
  /** 1-based line number for text files, when known. */
  line?: number;
  /** Short, redacted excerpt. Secret-looking values are always masked. */
  excerpt?: string;
  /** OWASP Top 10 for Agentic Applications ids this maps to (a mapping, not a certification). */
  owasp_asi: string[];
  /** Documentation backing the rule (official docs for permission rules). */
  references: string[];
}

/** A package the caller wants checked against the advisory database (API side). */
export interface PackageRef {
  ecosystem: "npm" | "pypi" | "docker" | "unknown";
  name: string;
  /** Exact version when pinned; undefined when the config does not pin one. */
  version?: string;
  /** Where the reference came from, e.g. "mcp.json#servers.filesystem". */
  source: string;
}

export type Verdict = "high_risk" | "review" | "no_known_issue";

export interface ScanReport {
  schema_version: "aivdb-scan-v1";
  rules_version: string;
  target_kind: TargetKind;
  /** SHA-256 of the normalized input, for blacklist lookups. Hex, lowercase. */
  fingerprint_sha256: string;
  risk_score: number;
  /**
   * "no_known_issue" means no rule matched. It is NOT a statement that the
   * target is safe; callers must not present it that way.
   */
  verdict: Verdict;
  findings: Finding[];
  /** Packages extracted for an advisory lookup; the engine does not look them up itself. */
  packages: PackageRef[];
}
