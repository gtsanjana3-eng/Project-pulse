// Password hashing (PBKDF2-HMAC-SHA256) and signed expiring bearer tokens (HMAC-SHA256).
import { createHmac, pbkdf2, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { eq } from "drizzle-orm";
import { db } from "../db/index.js";
import { appSecrets } from "../db/schema.js";
import { authError, validation } from "./errors.js";

const pbkdf2Async = promisify(pbkdf2);
const ITER = 200_000;
const TOKEN_TTL = 3600;
const EMAIL_RE = /^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$/;
const b64 = (b: Buffer) => b.toString("base64url");

export function normalizeEmail(email: unknown) {
  const e = String(email ?? "").trim().toLowerCase();
  if (!EMAIL_RE.test(e)) throw validation("invalid email");
  return e;
}
export function checkPasswordPolicy(pw: unknown): asserts pw is string {
  if (typeof pw !== "string" || pw.length < 10 || pw.length > 200) throw validation("password must be 10-200 characters");
}
export async function hashPassword(pw: string, iterations = ITER) {
  const salt = randomBytes(16);
  return `pbkdf2$${iterations}$${salt.toString("hex")}$${(await pbkdf2Async(pw, salt, iterations, 32, "sha256")).toString("hex")}`;
}
export async function verifyPassword(pw: string, stored: string) {
  const [, it, salt, dk] = stored.split("$");
  if (!it || !salt || !dk) return false;
  const got = await pbkdf2Async(pw, Buffer.from(salt, "hex"), Number(it), dk.length / 2, "sha256");
  return timingSafeEqual(got, Buffer.from(dk, "hex"));
}

let dummy: Promise<string> | undefined;
export const dummyHash = () => (dummy ??= hashPassword("dummy-password"));

// PP_SECRET if configured; otherwise a random secret generated once and kept in the database.
let secret: Promise<string> | undefined;
export function getSecret() {
  return (secret ??= (async () => {
    const env = process.env.PP_SECRET;
    if (env && env.length >= 32) return env;
    await db.insert(appSecrets).values({ name: "token_secret", value: randomBytes(48).toString("base64url") }).onConflictDoNothing();
    const [row] = await db.select().from(appSecrets).where(eq(appSecrets.name, "token_secret"));
    return row.value;
  })().catch(e => { secret = undefined; throw e; }));
}

export async function makeToken(userId: string) {
  const body = b64(Buffer.from(JSON.stringify({ sub: userId, exp: Math.floor(Date.now() / 1000) + TOKEN_TTL })));
  return body + "." + b64(createHmac("sha256", await getSecret()).update(body).digest());
}
export async function verifyToken(token: string): Promise<string> {
  const [body, sig] = token.split(".");
  if (!body || !sig) throw authError("invalid token");
  const good = Buffer.from(b64(createHmac("sha256", await getSecret()).update(body).digest()));
  const given = Buffer.from(sig);
  if (given.length !== good.length || !timingSafeEqual(given, good)) throw authError("invalid token");
  let data: { sub: string; exp: number };
  try { data = JSON.parse(Buffer.from(body, "base64url").toString()); } catch { throw authError("invalid token"); }
  if (typeof data?.sub !== "string" || !(data.exp >= Date.now() / 1000)) throw authError("token expired");
  return data.sub;
}
