/**
 * Mask secret-looking values before anything is placed in a report. Reports may
 * be printed in CI logs or sent to the API, so they must never carry a live key.
 */

const SECRET_PATTERNS: RegExp[] = [
  /\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b/g, // OpenAI/Stripe-style keys
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, // GitHub tokens
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, // Slack tokens
  /\bAKIA[0-9A-Z]{16}\b/g, // AWS access key id
  /\bAIza[0-9A-Za-z_-]{30,}\b/g, // Google API key
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, // JWT
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
];

const ASSIGNMENT = /((?:api[_-]?key|token|secret|password|passwd|credential|auth)[A-Za-z0-9_]*\s*[:=]\s*["']?)([^\s"']{6,})/gi;

export function redact(text: string): string {
  let out = text;
  for (const pattern of SECRET_PATTERNS) out = out.replace(pattern, "[REDACTED]");
  out = out.replace(ASSIGNMENT, (_m, prefix: string) => `${prefix}[REDACTED]`);
  return out;
}

/** True when a value looks like a literal credential rather than a reference such as ${VAR}. */
export function looksLikeSecretLiteral(value: string): boolean {
  if (/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(value.trim())) return false;
  return redact(value) !== value || /^[A-Za-z0-9+/_-]{32,}={0,2}$/.test(value.trim());
}

export function excerpt(line: string, max = 160): string {
  const clean = redact(line.trim());
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}
