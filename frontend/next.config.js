// frontend/next.config.js - Version corrigée
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Supprimer experimental.appDir car c'est maintenant stable dans Next.js 14
  webpack: (config, { isServer }) => {
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
      };
    }
    return config;
  },
};

module.exports = nextConfig;
