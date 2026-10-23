// NOTE (drill): VULNERABLE — Stripe webhook with NO signature verification.
// Anyone can POST a forged checkout.session.completed and activate a plan.
import { createAdminClient } from "@/lib/supabase-server";

export async function POST(req: Request) {
  const event = await req.json();

  if (event.type === "checkout.session.completed") {
    const supabase = createAdminClient();
    const customerId = event.data?.object?.customer;
    const email = event.data?.object?.customer_details?.email;
    await supabase
      .from("subscriptions")
      .upsert({ customer_id: customerId, email, plan: "pro", active: true });
  }

  return Response.json({ received: true });
}
