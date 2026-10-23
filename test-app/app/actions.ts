"use server";

// NOTE (drill): VULNERABLE — mass assignment + client-trusted ownership.
// `userId` comes from the form (attacker-controlled) and the whole body is
// spread into the update, so a caller can set `role: "admin"` or overwrite
// another user's profile.
import { supabase } from "@/lib/supabase";

export async function updateProfile(formData: FormData) {
  const userId = formData.get("userId") as string; // attacker-controlled
  const body = JSON.parse(formData.get("profile") as string);

  const { error } = await supabase.from("profiles").update(body).eq("id", userId);
  if (error) throw new Error(error.message);
  return { success: true };
}
