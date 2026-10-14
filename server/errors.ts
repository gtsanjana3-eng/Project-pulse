export class HttpError extends Error {
  constructor(public status: number, message: string, public headers: Record<string, string> = {}) { super(message); }
}
export const notFound = (m: string) => new HttpError(404, m);
export const validation = (m: string) => new HttpError(422, m);
export const authError = (m: string) => new HttpError(401, m);
export const conflict = (m: string) => new HttpError(409, m);
export const rateLimited = (retryAfter: number) => new HttpError(429, "rate limit exceeded", { "Retry-After": String(retryAfter) });
