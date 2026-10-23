// SECURE — intentionally public health endpoint. No secrets, no user data.
export async function GET() {
  return Response.json({ status: "ok", uptime: process.uptime() });
}
