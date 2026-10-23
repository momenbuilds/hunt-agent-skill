// SECURE — Stripe webhook with signature verification on the raw body.
import Stripe from "stripe";
import { createAdminClient } from "@/lib/supabase-server";

export async function POST(req: Request) {
  const payload = await req.text();
  const signature = req.headers.get("stripe-signature");
  const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(
      payload,
      signature ?? "",
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  } catch {
    return new Response("Invalid signature", { status: 400 });
  }

  if (event.type === "checkout.session.completed") {
    const supabase = createAdminClient();
    await supabase.from("subscriptions").upsert({
      customer_id: event.data.object.customer as string,
      email: event.data.object.customer_details?.email ?? null,
      plan: "pro",
      active: true,
    });
  }

  return Response.json({ received: true });
}
