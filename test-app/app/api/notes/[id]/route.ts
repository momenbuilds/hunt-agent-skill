// NOTE (drill): VULNERABLE — no auth and no ownership check.
// findNoteById interpolates the id into raw SQL (SQLi) and, because the
// shared client is service-role, bypasses any RLS.
import { findNoteById } from "@/lib/db";

export async function GET(
  _req: Request,
  { params }: { params: { id: string } }
) {
  const { id } = await params;
  const note = await findNoteById(id);
  if (!note) return new Response("Not found", { status: 404 });
  return Response.json(note);
}
