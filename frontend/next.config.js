/** @type {import('next').NextConfig} */
const staticDemo = process.env.NEXT_PUBLIC_STATIC_DEMO === "1";

const nextConfig = {
  // GitHub Pages build: plain static export under /<repo-name>.
  ...(staticDemo ? {
    output: "export",
    basePath: process.env.NEXT_PUBLIC_BASE_PATH || "",
    images: { unoptimized: true },
    trailingSlash: true,
  } : {}),
  // Standalone output traces only the files actually needed at runtime
  // into .next/standalone, which is what Dockerfile copies -- without
  // this, a production image would need the full node_modules tree
  // (hundreds of MB of devDependencies and unused transitive deps) just
  // to run `next start`.
  ...(staticDemo ? {} : { output: "standalone" }),
  reactStrictMode: true,
};

module.exports = nextConfig;
