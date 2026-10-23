// NOTE (drill): VULNERABLE — no authentication whatsoever.
// Anyone (unauthenticated) can list every note in the database.
import { supabase } from "@/lib/supabase";

export async function GET() {
  const { data, error } = await supabase.from("notes").select("*");
  if (error) return new Response(error.message, { status: 500 });
  return Response.json(data);
}
