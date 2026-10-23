// SECURE — parameterized / query-builder data access.
import { createAdminClient } from "./supabase-server";

export async function searchDocumentsSafe(userId: string, term: string) {
  const supabase = createAdminClient();
  const { data, error } = await supabase
    .from("documents")
    .select("id, title, created_at")
    .eq("user_id", userId)
    .ilike("title", `%${term}%`)
    .limit(50);
  if (error) throw error;
  return data;
}

export async function findDocumentByIdSafe(id: string, userId: string) {
  const supabase = createAdminClient();
  const { data, error } = await supabase
    .from("documents")
    .select("id, title, body")
    .eq("id", id)
    .eq("user_id", userId)
    .maybeSingle();
  if (error) throw error;
  return data;
}
