/** @type {import('next').NextConfig} */
const nextConfig = {
  // NOTE (drill): no security headers configured here.
  // An auditor should note missing HSTS / X-Content-Type-Options / frame
  // protection as a single Low finding for an app with sessions.
};

module.exports = nextConfig;
