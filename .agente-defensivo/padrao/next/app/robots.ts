import type { MetadataRoute } from 'next'

const aiAgents = [
  'GPTBot',
  'OAI-SearchBot',
  'ChatGPT-User',
  'Google-Extended',
  'Applebot-Extended',
  'ClaudeBot',
  'Claude-SearchBot',
  'Claude-User',
  'Claude-Web',
  'anthropic-ai',
  'PerplexityBot',
  'Perplexity-User',
  'CCBot',
  'Bytespider',
  'Amazonbot',
  'cohere-ai',
  'Diffbot',
  'AI2Bot',
  'FacebookBot',
  'meta-externalagent',
  'meta-externalfetcher',
  'DuckAssistBot',
]

const excludedRoutes = ['/api', '/embed', '/entrar', '/painel']

export default function robots(): MetadataRoute.Robots {
  const sitemap = process.env.ROBOTS_SITEMAP_URL?.trim()

  return {
    rules: [
      { userAgent: aiAgents, disallow: '/' },
      {
        userAgent: '*',
        allow: '/',
        disallow: excludedRoutes.flatMap((path) => [
          `${path}$`,
          `${path}/`,
          `${path}?`,
        ]),
      },
    ],
    ...(sitemap ? { sitemap } : {}),
  }
}
