/**
 * High-risk permission combination rules (Over-privilege Signatures).
 *
 * First provider: GitHub OAuth app scopes. Scope names and meanings follow
 * GitHub's official documentation linked in every rule; do not add a scope here
 * without checking that page.
 */
import type { Severity } from "../types.js";

export const GITHUB_SCOPES_DOC =
  "https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps";

export interface PermissionRule {
  id: string;
  provider: "github";
  severity: Severity;
  title: string;
  detail: string;
  owasp_asi: string[];
  /** Every scope listed must be granted for the rule to match. */
  requires_all: string[];
  references: string[];
}

export const PERMISSION_RULES: PermissionRule[] = [
  {
    id: "PRM-GH-001",
    provider: "github",
    severity: "critical",
    title: "Can rewrite CI workflows with full repository access",
    detail:
      "`repo` plus `workflow` lets the agent change GitHub Actions workflow files. A hijacked agent can add a workflow that " +
      "prints repository secrets or pushes a backdoor, so these two should not sit on one agent token.",
    owasp_asi: ["ASI03"],
    requires_all: ["repo", "workflow"],
    references: [GITHUB_SCOPES_DOC],
  },
  {
    id: "PRM-GH-002",
    provider: "github",
    severity: "high",
    title: "Can delete repositories",
    detail: "`delete_repo` lets the agent delete administrable repositories. Agents almost never need it.",
    owasp_asi: ["ASI03"],
    requires_all: ["delete_repo"],
    references: [GITHUB_SCOPES_DOC],
  },
  {
    id: "PRM-GH-003",
    provider: "github",
    severity: "high",
    title: "Organization administration",
    detail:
      "`admin:org` gives full control of the organization, its teams and memberships. An agent with it can grant itself or " +
      "others further access.",
    owasp_asi: ["ASI03"],
    requires_all: ["admin:org"],
    references: [GITHUB_SCOPES_DOC],
  },
  {
    id: "PRM-GH-004",
    provider: "github",
    severity: "high",
    title: "Can publish packages from repositories it can modify",
    detail:
      "`repo` plus `write:packages` lets one token both change code and publish packages, which is a supply-chain path " +
      "if the agent is steered by untrusted input.",
    owasp_asi: ["ASI03", "ASI04"],
    requires_all: ["repo", "write:packages"],
    references: [GITHUB_SCOPES_DOC],
  },
  {
    id: "PRM-GH-005",
    provider: "github",
    severity: "medium",
    title: "Full repository access",
    detail:
      "`repo` grants read and write access to all public and private repositories the user can reach. Prefer a " +
      "fine-grained token limited to the repositories this agent's task needs.",
    owasp_asi: ["ASI03"],
    requires_all: ["repo"],
    references: [GITHUB_SCOPES_DOC],
  },
];
