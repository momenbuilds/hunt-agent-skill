// NOTE (drill): VULNERABLE — shared Supabase client created with the
// service-role key. This module is imported by Client Components
// (see app/page.tsx), so the key is bundled into the browser.
import { createClient } from "@supabase/supabase-js";

export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!
);
