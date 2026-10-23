// NOTE (drill): VULNERABLE (SSRF) — fetches a caller-supplied URL server-side
// with no scheme/host validation. An attacker can hit internal services or
// cloud metadata endpoints (e.g. http://169.254.169.254/...).
export async function POST(req: Request) {
  const { url } = await req.json();
  const response = await fetch(url);
  const body = await response.text();
  return new Response(body.slice(0, 5000), {
    headers: { "content-type": "text/plain" },
  });
}
