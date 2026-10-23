// NOTE (drill): VULNERABLE (IDOR / BOLA) — requires login, but never checks
// that the document belongs to the caller. Any authenticated user can read
// any document by id. The table also has RLS enabled with USING (true)
// (see migrations/0002), so the database layer does not save it either.
import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

export async function GET(
  _req: Request,
  { params }: { params: { id: string } }
) {
  const cookieStore = await cookies();
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll: () => cookieStore.getAll(),
        setAll: () => {},
      },
    }
  );

  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });

  const { id } = await params;
  // BUG: missing .eq("user_id", user.id)
  const { data } = await supabase
    .from("documents")
    .select("*")
    .eq("id", id)
    .single();

  if (!data) return new Response("Not found", { status: 404 });
  return Response.json(data);
}
