import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// NOTE (drill): middleware checks a session cookie for /dashboard only.
// The matcher explicitly excludes /api — so API routes receive NO
// middleware-level auth. Every route handler must protect itself.
// This is context for the endpoint findings, not a standalone vulnerability.

export function middleware(request: NextRequest) {
  const session = request.cookies.get("session");
  if (!session) {
    return NextResponse.redirect(new URL("/login", request.url));
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*"],
};
