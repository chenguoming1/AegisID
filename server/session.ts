import crypto from "crypto";
import type { Request, Response } from "express";
import { loadDb, User } from "./store";

// ---------------------------------------------------------------------------
// Server-side session store shared by the password/MFA login (auth.ts) and the
// OIDC login (oidc.ts). A session is just an httpOnly cookie holding an opaque
// id that maps to a directory user id. In-memory is fine for this single-node
// demo; swap for Redis/DB in production.
// ---------------------------------------------------------------------------

const COOKIE = "aegis_sid";
const TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

const sessions = new Map<string, { userId: string; createdAt: number }>();

export function readCookie(req: Request, name: string): string | null {
  const header = req.headers.cookie || "";
  for (const pair of header.split(";")) {
    const i = pair.indexOf("=");
    if (i < 0) continue;
    if (pair.slice(0, i).trim() === name) return decodeURIComponent(pair.slice(i + 1).trim());
  }
  return null;
}

export function createSession(res: Response, userId: string): string {
  const sid = crypto.randomUUID();
  sessions.set(sid, { userId, createdAt: Date.now() });
  res.setHeader(
    "Set-Cookie",
    `${COOKIE}=${sid}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${Math.floor(TTL_MS / 1000)}`,
  );
  return sid;
}

export function destroySession(req: Request, res: Response): void {
  const sid = readCookie(req, COOKIE);
  if (sid) sessions.delete(sid);
  res.setHeader("Set-Cookie", `${COOKIE}=; HttpOnly; Path=/; Max-Age=0`);
}

export function getSessionUserId(req: Request): string | null {
  const sid = readCookie(req, COOKIE);
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s) return null;
  if (Date.now() - s.createdAt > TTL_MS) {
    sessions.delete(sid);
    return null;
  }
  return s.userId;
}

export function getSessionUser(req: Request): User | null {
  const id = getSessionUserId(req);
  if (!id) return null;
  return loadDb().users.find((u) => u.id === id) || null;
}
