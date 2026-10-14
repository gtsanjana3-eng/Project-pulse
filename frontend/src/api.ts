const BASE = (import.meta as any).env?.VITE_API_URL ?? "http://localhost:8000";
let token: string | null = sessionStorage.getItem("pp_token");
export const setToken = (t: string | null) => { token = t; t ? sessionStorage.setItem("pp_token", t) : sessionStorage.removeItem("pp_token"); };
export const hasToken = () => !!token;
async function req(path: string, init: RequestInit = {}): Promise<Response> {
  const r = await fetch(BASE + path, { ...init, headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}), ...init.headers } });
  if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(r.status === 429 ? "Too many requests - try again shortly." : d.detail ?? `Error ${r.status}`); }
  return r;
}
const json = async <T,>(p: string, init?: RequestInit): Promise<T> => (await req(p, init)).json();
export const post = <T,>(p: string, body?: unknown) => json<T>(p, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });
export const get = <T,>(p: string) => json<T>(p);
export const patch = <T,>(p: string, body: unknown) => json<T>(p, { method: "PATCH", body: JSON.stringify(body) });
export async function download(path: string, name: string) {
  const b = await (await req(path)).blob(); const a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = name; a.click(); URL.revokeObjectURL(a.href);
}
export interface Category { category: string; score: number | null; status: string; checks_run: number; confidence: string }
export interface Finding { key: string; title: string; category: string; severity: string; evidence: string; recommended_fix: string; status: string }
export interface Audit { id: string; project_id: string; attempt_no: number; status: string; scoring_version: string | null; overall: number | null; created_at: string; effective_weights: Record<string, number>; categories: Category[]; findings: Finding[] }
export interface Project { id: string; name: string; url: string }
export interface Page<T> { total: number; items: T[] }
export interface Comparison { earlier: string; later: string; overall: { before: number | null; after: number | null; delta: number | null; comparable: boolean }; categories: Record<string, { before: number | null; after: number | null; delta: number | null }>; findings: { resolved: string[]; new: string[]; remaining: string[] }; notes: string[] }
