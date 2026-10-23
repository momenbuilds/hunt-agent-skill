// NOTE (drill): VULNERABLE (BFLA) — admin user list with no role check.
// Any authenticated (even unauthenticated) caller can enumerate all users.
// Uses the service-role client, so RLS is irrelevant.
import { createAdminClient } from "@/lib/supabase-server";

export async function GET() {
  const supabase = createAdminClient();
  const { data, error } = await supabase
    .from("profiles")
    .select("id, email, role, created_at");
  if (error) return new Response(error.message, { status: 500 });
  return Response.json(data);
}
