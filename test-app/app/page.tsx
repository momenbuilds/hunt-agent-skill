"use client";

// NOTE (drill): VULNERABLE (stored XSS) — renders user-submitted HTML with
// dangerouslySetInnerHTML and no sanitization. Also imports the vulnerable
// shared Supabase client (service-role key ships to the browser).
import { useEffect, useState } from "react";
import { supabase } from "@/lib/supabase";

export default function HomePage() {
  const [bio, setBio] = useState("");

  useEffect(() => {
    supabase
      .from("profiles")
      .select("bio")
      .limit(1)
      .maybeSingle()
      .then(({ data }) => setBio(data?.bio ?? ""));
  }, []);

  return (
    <main>
      <h1>Community bios</h1>
      {/* user-controlled HTML rendered unsanitized */}
      <div dangerouslySetInnerHTML={{ __html: bio }} />
    </main>
  );
}
