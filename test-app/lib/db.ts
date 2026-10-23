// NOTE (drill): VULNERABLE — raw SQL built by string interpolation.
// `userId` and `term` trace to request input in the routes that call this.
import { createAdminClient } from "./supabase-server";

export async function searchNotes(userId: string, term: string) {
  const supabase = createAdminClient();
  const query = `SELECT * FROM notes WHERE user_id = '${userId}' AND content ILIKE '%${term}%'`;
  const { data, error } = await supabase.rpc("query", { q: query });
  if (error) throw error;
  return data;
}

export async function findNoteById(id: string) {
  const supabase = createAdminClient();
  const { data, error } = await supabase.rpc("query", {
    q: `SELECT * FROM notes WHERE id = '${id}'`,
  });
  if (error) throw error;
  return data;
}
