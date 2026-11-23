import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX();

/**
 * Static docs served at rabbitlock.com/docs. The main site rewrites /docs/* to this build,
 * so every route and asset lives under the /docs base path.
 * @type {import('next').NextConfig}
 */
const config = {
  output: 'export',
  basePath: '/docs',
  trailingSlash: false,
  reactStrictMode: true,
  images: { unoptimized: true },
};

export default withMDX(config);
