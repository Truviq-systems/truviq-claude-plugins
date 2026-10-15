/**
 * Production: a static export (`out/`) that scripts/ship.mjs copies into the plugin,
 * where the plugin's Python server (`truviq.py dashboard`) serves it with /api/*.
 * Development: `next dev` proxies /api/* to a running `truviq.py dashboard` on :8787.
 */
const isDev = process.env.NODE_ENV === "development";

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  images: { unoptimized: true },
  ...(isDev
    ? {
        async rewrites() {
          return [{ source: "/api/:path*", destination: "http://127.0.0.1:8787/api/:path*" }];
        },
      }
    : { output: "export", trailingSlash: false }),
};

export default nextConfig;
