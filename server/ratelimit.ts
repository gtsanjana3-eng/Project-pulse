// Sliding-window limiter backed by the database so it holds across function instances.
import { and, asc, count, eq, gte, lt } from "drizzle-orm";
import { db } from "../db/index.js";
import { rateHits } from "../db/schema.js";
import { rateLimited } from "./errors.js";

export async function checkRate(key: string, limit: number, windowSeconds: number) {
  const since = new Date(Date.now() - windowSeconds * 1000);
  const [{ n }] = await db.select({ n: count() }).from(rateHits).where(and(eq(rateHits.key, key), gte(rateHits.at, since)));
  if (n >= limit) {
    const [oldest] = await db.select({ at: rateHits.at }).from(rateHits).where(and(eq(rateHits.key, key), gte(rateHits.at, since))).orderBy(asc(rateHits.at)).limit(1);
    throw rateLimited(Math.max(1, Math.ceil((oldest.at.getTime() + windowSeconds * 1000 - Date.now()) / 1000)));
  }
  await db.insert(rateHits).values({ key });
  if (Math.random() < 0.02) await db.delete(rateHits).where(lt(rateHits.at, new Date(Date.now() - 86_400_000))); // occasional cleanup
}
