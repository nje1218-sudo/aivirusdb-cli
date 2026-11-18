/**
 * Line-oriented static signatures for Agent Skill files (SKILL.md), project rule
 * files (.cursorrules and similar), prompt templates and workflow scripts.
 *
 * These are heuristics. Each rule documents a benign counter-example in the
 * tests; a match means "a human should look", not "proven malicious".
 */
import type { Severity } from "../types.js";

export interface TextRule {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  owasp_asi: string[];
  /** Any pattern matching a line triggers the rule. */
  patterns: RegExp[];
}

const CREDENTIAL_PATHS =
  String.raw`(?:\.env(?:\.[a-z]+)?\b|\.aws/credentials|\.ssh/id_[a-z0-9]+|id_rsa\b|\.npmrc\b|\.pypirc\b|\.git-credentials\b|\.netrc\b|\.docker/config\.json|\.kube/config|gcloud/(?:credentials|application_default_credentials))`;

export const TEXT_RULES: TextRule[] = [
  {
    id: "SKL001",
    severity: "high",
    title: "Reads local credential files",
    detail:
      "The file tells the agent to open a local credential store (.env, cloud or SSH keys, package registry tokens). " +
      "A skill rarely needs this, and it is the first step of credential theft through an agent.",
    owasp_asi: ["ASI03", "ASI04"],
    patterns: [
      new RegExp(String.raw`\b(?:cat|type|less|more|head|tail|read|open|load|print|source|get-content)\b[^\n]{0,60}${CREDENTIAL_PATHS}`, "i"),
      new RegExp(String.raw`\b(?:read|open|load|include|attach|upload|send|copy)\b[^\n]{0,40}\b(?:the\s+)?${CREDENTIAL_PATHS}`, "i"),
    ],
  },
  {
    id: "SKL002",
    severity: "critical",
    title: "Downloads and executes remote code",
    detail:
      "Remote content is piped straight into a shell or interpreter, so whoever controls that URL controls the agent's machine.",
    owasp_asi: ["ASI04", "ASI05"],
    patterns: [
      /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/i,
      /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:python3?|node|perl|ruby)\b/i,
      /\b(?:iex|invoke-expression)\b[^\n]{0,40}\b(?:iwr|invoke-webrequest|downloadstring|new-object\s+net\.webclient)/i,
      /\bpowershell(?:\.exe)?\b[^\n]{0,40}\s-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/i,
    ],
  },
  {
    id: "SKL003",
    severity: "critical",
    title: "Reverse shell pattern",
    detail: "The text contains a known reverse-shell construction that hands an interactive shell to a remote host.",
    owasp_asi: ["ASI05"],
    patterns: [
      /\b(?:ba)?sh\s+-i\s*>&?\s*\/dev\/tcp\//i,
      /\/dev\/tcp\/[0-9a-z.-]+\/\d{2,5}/i,
      /\b(?:nc|ncat|netcat)\b[^\n]{0,40}\s-(?:e|c)\s+\/bin\/(?:ba)?sh/i,
      /\bmkfifo\b[^\n]{0,80}\b(?:nc|ncat|netcat)\b/i,
      /socket\.socket\([^\n]{0,120}\bconnect\([^\n]{0,120}\b(?:pty\.spawn|subprocess\.call|os\.dup2)/i,
    ],
  },
  {
    id: "SKL004",
    severity: "critical",
    title: "Sends secrets or environment to a remote endpoint",
    detail:
      "Environment variables or credential files are sent over the network. This is the exfiltration step after a credential read.",
    owasp_asi: ["ASI03", "ASI05"],
    patterns: [
      /\b(?:env|printenv|set)\b\s*\|\s*(?:curl|wget|nc|ncat)\b/i,
      new RegExp(String.raw`\b(?:curl|wget)\b[^\n]{0,80}(?:-d|--data(?:-binary)?|--upload-file|-F|-T)\s*["']?@?[^\s"']*${CREDENTIAL_PATHS}`, "i"),
      /\b(?:curl|wget)\b[^\n]{0,120}\$\{?(?:[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*)\}?/,
    ],
  },
  {
    id: "SKL005",
    severity: "high",
    title: "Tells the agent to hide actions from the user",
    detail:
      "Instructions to act silently or keep something from the user are a hallmark of injected instructions. " +
      "Legitimate skills describe what they do; they do not ask to be concealed.",
    owasp_asi: ["ASI01", "ASI09"],
    patterns: [
      /\b(?:do\s+not|don['’]t|never)\s+(?:tell|inform|notify|mention\s+(?:this\s+)?to|show|reveal\s+(?:this\s+)?to|alert)\s+(?:the\s+)?(?:user|human|operator|developer)\b/i,
      /\bwithout\s+(?:telling|informing|notifying|asking|alerting)\s+(?:the\s+)?(?:user|human|operator)\b/i,
      /\b(?:silently|secretly|covertly)\s+(?:run|execute|send|upload|copy|read|install|modify)\b/i,
      /\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|guidelines)\b/i,
    ],
  },
  {
    id: "SKL006",
    severity: "high",
    title: "Decodes and runs an embedded payload",
    detail: "An encoded blob is decoded and executed. Encoding is used to keep the real command out of sight of a reviewer.",
    owasp_asi: ["ASI05"],
    patterns: [
      /\bbase64\s+(?:-d|--decode|-D)\b[^\n]{0,40}\|\s*(?:ba|z)?sh\b/i,
      /\b(?:eval|exec)\s*\(\s*(?:base64\.b64decode|atob|Buffer\.from)\s*\(/i,
      /\becho\s+["']?[A-Za-z0-9+/]{40,}={0,2}["']?\s*\|\s*base64\s+(?:-d|--decode)/i,
    ],
  },
  {
    id: "SKL007",
    severity: "high",
    title: "Disables approvals or sandboxing",
    detail:
      "The file asks the agent or tool to skip permission prompts or run outside its sandbox, which removes the human check on every later step.",
    owasp_asi: ["ASI03", "ASI05", "ASI09"],
    patterns: [
      /--dangerously-skip-permissions\b/i,
      /--(?:no-sandbox|disable-sandbox|allow-all-tools)\b/i,
      /\b(?:auto[- ]?approve|always\s+approve|approve\s+all)\b[^\n]{0,40}\b(?:commands|tools|actions|requests|everything)\b/i,
      /\byolo\s+mode\b/i,
    ],
  },
];
