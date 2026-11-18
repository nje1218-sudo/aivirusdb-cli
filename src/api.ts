/**
 * Optional advisory lookup through the AIVirusDB API.
 *
 * Only package names, ecosystems and versions are sent. File contents and
 * findings never leave the machine.
 */
import type { PackageRef } from "./engine/index.js";

export const DEFAULT_API_URL = "https://www.aivirusdb.com/v1/check";
const KEY_PATTERN = /^aivdb_[A-Za-z0-9_-]{43}$/;

export interface PackageResult {
  package: { ecosystem: string; name: string; version?: string; source?: string };
  verdict: "affected" | "not_known_affected" | "unknown";
  reason?: string;
  risk_score: number;
  matches: { id: string; title?: string; advisory_ids: string[]; severity?: string; evidence_url: string | null }[];
}

export interface LookupResult {
  packages: PackageResult[];
  usage?: { period: string; calls: number; quota: number };
  dataset?: { records: number; observed_at: string | null };
}

export type Fetch = (url: string, init: RequestInit) => Promise<Response>;

export class ApiError extends Error {
  constructor(public readonly code: string) { super(code); }
}

export async function lookupPackages(packages: PackageRef[], options: { apiKey: string; apiUrl?: string; fetch?: Fetch; timeoutMs?: number }): Promise<LookupResult> {
  if (!KEY_PATTERN.test(options.apiKey)) throw new ApiError("api_key_format_invalid");
  if (packages.length === 0) return { packages: [] };
  const url = options.apiUrl ?? DEFAULT_API_URL;
  if (!/^https:\/\//.test(url) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(url)) throw new ApiError("api_url_must_be_https");
  const doFetch = options.fetch ?? ((u, init) => fetch(u, init));
  const body = { packages: packages.slice(0, 100).map(p => ({ ecosystem: p.ecosystem, name: p.name, ...(p.version ? { version: p.version } : {}) })) };
  let response: Response;
  try {
    response = await doFetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${options.apiKey}` },
      body: JSON.stringify(body),
      redirect: "error",
      signal: AbortSignal.timeout(options.timeoutMs ?? 15_000),
    });
  } catch {
    throw new ApiError("api_unreachable");
  }
  if (!response.ok) {
    let code = `api_http_${response.status}`;
    try { const e = await response.json() as { error?: unknown }; if (typeof e.error === "string") code = e.error; } catch { /* keep status code */ }
    throw new ApiError(code);
  }
  const data = await response.json() as LookupResult;
  if (!data || !Array.isArray(data.packages)) throw new ApiError("api_response_invalid");
  return data;
}
