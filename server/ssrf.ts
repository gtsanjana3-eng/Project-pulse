// SSRF guard: validate URLs and resolve to globally-routable IPs only.
import { lookup } from "node:dns/promises";
import ipaddr from "ipaddr.js";

const ALLOWED_PORTS = new Set([80, 443, 8080, 8443]);
export class UnsafeURL extends Error {}

export interface Validated { url: URL; host: string; port: number; ip: string; family: 4 | 6 }

/** Every resolved address must be public; the caller connects to `ip` (not the hostname)
 *  so DNS rebinding between check and connect is impossible. */
export async function validateUrl(raw: unknown): Promise<Validated> {
  if (typeof raw !== "string" || raw.length > 2048) throw new UnsafeURL("invalid url");
  let u: URL;
  try { u = new URL(raw.trim()); } catch { throw new UnsafeURL("invalid url"); }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new UnsafeURL("only http/https allowed");
  if (u.username || u.password) throw new UnsafeURL("credentials in url not allowed");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (!host) throw new UnsafeURL("missing host");
  const port = u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
  if (!ALLOWED_PORTS.has(port)) throw new UnsafeURL(`port ${port} not allowed`);
  let ips: { address: string; family: number }[];
  try { ips = await lookup(host, { all: true }); } catch { throw new UnsafeURL("host could not be resolved"); }
  if (!ips.length) throw new UnsafeURL("host could not be resolved");
  for (const { address } of ips) {
    let addr = ipaddr.parse(address.split("%")[0]);
    if (addr.kind() === "ipv6" && (addr as ipaddr.IPv6).isIPv4MappedAddress()) addr = (addr as ipaddr.IPv6).toIPv4Address();
    if (addr.range() !== "unicast") throw new UnsafeURL("target resolves to a non-public address");
  }
  return { url: u, host, port, ip: ips[0].address, family: ips[0].family === 6 ? 6 : 4 };
}
