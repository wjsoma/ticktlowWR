# Proteção contra cópia e raspagem | WJSOMA

Use a política pública nas aplicações que dependem de Google, Bing e Google Notícias. Para áreas restritas, aplique autenticação, autorização e limites na API, inclusive quando o pedido chega diretamente ao servidor.

## 1. Publicar a política de rastreamento

| Arquivo do pacote | Destino |
| --- | --- |
| `next/app/robots.ts` | `app/robots.ts` ou `src/app/robots.ts` no Next.js App Router. O Next publica o resultado em `/robots.txt`. |
| `estatico/robots.txt` | Raiz pública de um site estático, Vite ou SPA. Configure o host para servir esse arquivo em `/robots.txt`, antes do fallback para o HTML. |
| `public/ai.txt` | `public/ai.txt` em Next.js ou Vite. Em hospedagem estática, coloque o arquivo ao lado do `robots.txt` na raiz publicada. Confira o titular, o contato institucional e os termos de cada site. |
| `next/lib/protect-calculator.ts` | `lib/protect-calculator.ts` ou `src/lib/protect-calculator.ts` em projetos que rodam Next.js no servidor. Ligue o módulo à sessão, à quota e ao cálculo que o projeto já usa. |

Publique uma única implementação de `/robots.txt` por host. Confira também os subdomínios e as versões com e sem `www` que servem conteúdo. Na FATYX, se o arquivo XML de produção estiver em `/sitemap.xml`, configure:

```dotenv
ROBOTS_SITEMAP_URL=https://fatyx.com.br/sitemap.xml
```

Em site estático, adicione a linha `Sitemap: https://fatyx.com.br/sitemap.xml` ao final do arquivo, usando o endereço XML real de cada domínio. Se o projeto ainda não publica um sitemap, deixe essa linha ausente. [Next.js — robots.txt](https://nextjs.org/docs/app/api-reference/file-conventions/metadata/robots)

- Os buscadores tradicionais têm acesso às páginas públicas. As exclusões atingem `/api`, `/embed`, `/entrar` e `/painel`, inclusive subrotas e a forma com parâmetros. Revise a lista se a aplicação serve uma dessas seções para busca. `/api-docs`, páginas públicas com parâmetros e recursos como CSS e JS seguem acessíveis. [Google — interpretação de robots.txt](https://developers.google.com/crawling/docs/robots-txt/robots-txt-spec?hl=pt-BR)
- O perfil do pacote pede bloqueio de coleta para treinamento, busca e navegação assistida por IA. Isso pode reduzir a presença em respostas do ChatGPT, Claude, Perplexity e DuckDuckGo AI. Alguns agentes acionados por usuários podem ignorar o arquivo. A autenticação e o firewall aplicam a restrição no servidor. [OpenAI — crawlers](https://developers.openai.com/api/docs/bots) · [Anthropic — crawlers](https://support.claude.com/pt/articles/8896518-a-anthropic-rastreia-dados-da-web-e-como-os-proprietarios-de-sites-podem-bloquear-o-rastreador) · [Perplexity — crawlers](https://docs.perplexity.ai/docs/resources/perplexity-crawlers) · [DuckDuckGo — DuckAssistBot](https://duckduckgo.com/duckduckgo-help-pages/results/duckassistbot)
- `Google-Extended` e `Applebot-Extended` são controles declarados no `robots.txt`. Preserve os agentes de busca convencionais. Para restringir trechos específicos usados nas Visões Gerais Criadas por IA ou no Modo IA do Google, use `data-nosnippet` nos trechos em questão. Isso também pode afetar o snippet na Busca. [Google — rastreadores comuns](https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers) · [Google — recursos de IA e seu site](https://developers.google.com/search/docs/appearance/ai-features?hl=pt-BR) · [Apple — Applebot](https://support.apple.com/pt-br/119829)
- Em um app inteiramente privado, publique `User-agent: *` seguido de `Disallow: /` e exija autenticação nas páginas e APIs, inclusive nas URLs de preview. Em apps públicos, proteja previews que tenham versões inéditas, conteúdo privado ou recursos pagos. [RFC 9309](https://www.rfc-editor.org/rfc/rfc9309.html) · [Vercel — Deployment Protection](https://vercel.com/docs/deployment-protection)

## 2. Ajustar os metadados

Remova o campo `other.robots` com `noai, noimageai` do layout global. Para uma página acessível que você quer manter fora dos resultados, por exemplo a tela de login, use o campo nativo do Next nessa página ou no seu layout específico:

```ts
import type { Metadata } from 'next'

export const metadata: Metadata = {
  robots: { index: false },
}
```

Para o exemplo da tela de login, remova `/entrar` de `excludedRoutes` ou as três exclusões correspondentes do arquivo estático. O Google precisa poder ler a instrução para aplicar `noindex`. Em PDFs ou respostas sem HTML, use `X-Robots-Tag: noindex` quando precisar controlar indexação. Arquivos reservados exigem autorização e, quando aplicável, links temporários. [Google — metatags e cabeçalhos de indexação](https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag?hl=pt-BR)

## 3. Aplicar as regras no servidor

| Superfície | Controle |
| --- | --- |
| Projetos na Vercel | No projeto, abra **Security → Firewall → Rules → Bot Management → AI Bots**. Confira a identificação do tráfego em **Log** e, no perfil mais restritivo, configure **Block** para **AI crawlers** e **AI assistants**. Verifique Google/Bing, previews sociais e integrações antes de ampliar as regras. |
| APIs públicas ou caras | Configure um limite de rajada no firewall por rota, método e IP. Use o volume legítimo observado como referência. Ative resposta `429` ao exceder o limite após validar a regra com tráfego real. Preserve chamadas de parceiros com credenciais e regras específicas. Aplique desafios de navegador a fluxos compatíveis e use quotas nas APIs. |
| Ferramentas autenticadas | Autorize pelo usuário, pela organização e pelo direito ao recurso. Conte quotas por conta e operação em Redis ou Postgres com atualização atômica, inclusive com várias instâncias. Controle janela histórica, paginação e quantidade de registros por resposta. Mantenha exportações em quotas próprias. |
| Sites atendidos pelo proxy Cloudflare | Use **AI Crawl Control** para crawlers identificados e regras de WAF e limite por rota para abuso restante. Aplique a política no ponto que recebe o tráfego e cubra eventuais URLs alternativas que exponham o mesmo conteúdo. |
| Arquivos e dados premium | Armazene em bucket privado. Gere link de baixa duração após verificar permissão e registre o identificador da exportação para poder localizar sua origem. Retorne `Cache-Control: private, no-store` nas respostas personalizadas. |

[Vercel — regras de AI Bots](https://vercel.com/changelog/block-ai-crawlers-and-assistants-independently-with-managed-rules) · [Vercel — rate limiting](https://vercel.com/docs/vercel-firewall/vercel-waf/rate-limiting) · [Cloudflare — AI Crawl Control e Bots](https://developers.cloudflare.com/ai-crawl-control/configuration/ai-crawl-control-with-bots/) · [OWASP — limites de consumo da API](https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/)

### Proteger uma calculadora existente

Mantenha a função de cálculo e as chaves em módulos exclusivos do servidor. No `route.ts`, conecte as funções já usadas pela aplicação ao módulo do pacote. Os nomes de importação abaixo representam pontos de integração:

```ts
import { protectCalculator } from '@/lib/protect-calculator'
import { verifySession } from '@/lib/auth'
import { canUseTool, consumeQuota, calculate } from '@/lib/calculadora'

export const POST = protectCalculator({
  verifySession,
  canUseTool,
  consumeQuota,
  calculate,
})
```

1. `verifySession(request)` valida a credencial no servidor e retorna `{ userId }` ou `null`. Quando usada autenticação por cookies, aplique as verificações de origem/CSRF previstas pelo projeto a requisições que alteram estado.
2. `canUseTool(session)` confere no servidor o acesso à ferramenta. Autorize o usuário em cada consulta de dados vinculada a uma conta, organização, exportação ou recurso específico, usando a sessão verificada.
3. `consumeQuota(session)` desconta uma unidade de forma atômica para aquela conta e ferramenta. Retorne `{ allowed: true }` ou `{ allowed: false, retryAfterSeconds }`. Faça a operação no armazenamento compartilhado e deixe falhas excepcionais produzirem `503`.
4. `calculate(request, session)` valida o tipo e o tamanho da entrada antes de processar, consulta apenas dados autorizados e retorna `{ ok: true, data }` com os campos necessários na UI. Para erro esperado, retorne `{ ok: false, status, error }` com um código de erro fixo. O módulo aceita `400`, `404`, `413` e `422`. Registre falhas operacionais nos adaptadores sem credenciais nem payloads sensíveis.

Opções da v4, todas opcionais e compatíveis com o uso anterior:

- `parseInput(request, session)` valida a entrada **antes** de consumir quota e entrega o valor já tipado a `calculate(input, session)`.
- `allowedOrigins: ['https://fatyx.com.br']` recusa com `403` requisições que alteram estado vindas de outra origem (CSRF com sessão por cookie).
- `maxBodyBytes` (padrão 64 KiB) responde `413` pelo `Content-Length`; para corpo em streaming, limite também no `parseInput`.
- `onError(error, { userId, stage })` recebe falhas inesperadas para o monitoramento, sem payload.

O módulo responde `401` sem sessão válida, `403` sem permissão, `429` com `Retry-After` ao exceder a quota e `503` se uma dependência falhar. Um projeto estático precisa de uma API de servidor para aplicar os mesmos controles. [Next.js — segurança de dados](https://nextjs.org/docs/app/guides/data-security) · [Next.js — autenticação](https://nextjs.org/docs/app/guides/authentication)

### Prioridades na FATYX

| Superfície | Aplicação |
| --- | --- |
| Redação e páginas públicas | Deixe matérias, metodologia e as páginas das ferramentas acessíveis à busca convencional. Sirva resumos e resultados públicos suficientes para a página. |
| IFCD, poder de compra, FIPE × cesta básica e Placar Aberto | Execute a implementação proprietária e as consultas pesadas no servidor. Entregue os valores já calculados. Quando houver amostra pública, limite o volume e o intervalo consultáveis. Reserve operações em lote, históricos completos e exportações para sessões autorizadas. |
| Widgets licenciados para incorporação | Preserve a incorporação autorizada e o crédito existente. Caso use `frame-ancestors` para bloquear iframes em telas restritas, configure-o por rota e valide os widgets em um domínio parceiro. |
| Supabase e rotas diretas | Ative e teste RLS nas tabelas expostas, com políticas por titular ou organização. Mantenha chaves secretas e `service_role` no servidor. Essa credencial pode contornar RLS. Restrinja o acesso aos dados brutos também no Supabase porque as chamadas diretas ao serviço passam por outro domínio. |
| Painel com URLs por hash | `/app#/lab` e `/app#painel` carregam `/app` no servidor. Proteja as APIs de cada tela e aplique a autorização à rota real quando o app inteiro for privado. |

[FATYX — widgets](https://fatyx.com.br/ferramentas) · [FATYX — fontes e metodologia](https://fatyx.com.br/metodologia.html) · [Supabase — RLS](https://supabase.com/docs/guides/database/postgres/row-level-security)

Revise o bundle, a pasta pública e os artefatos de build para tirar código reservado, chaves e mapas de código publicados. No Next.js, os mapas de código do navegador já ficam desabilitados em produção por padrão. Preserve mapas enviados de modo privado à ferramenta de monitoramento, se usados. [Next.js — productionBrowserSourceMaps](https://nextjs.org/docs/pages/api-reference/config/next-config-js/productionBrowserSourceMaps)

## 4. Verificar antes da publicação

- Confirme que `/robots.txt` volta como texto, `/ai.txt` exibe o aviso, e o endereço anunciado no sitemap devolve XML com URLs canônicas públicas. Rode as verificações no host final e em cada host alternativo em uso.
- Valide matérias, resultados de busca, preview social, login, widgets e webhooks. No painel do firewall, confirme quais classes de bot e rotas dispararam cada regra. Valide a ação de bloqueio em preview antes de ativá-la em produção.
- Em ambiente de teste, confirme que a API nega uma requisição sem sessão, nega acesso entre duas contas de teste, limita um usuário de teste com quota baixa e devolve somente o resultado autorizado. Confirme que nem CDN nem cache compartilhado armazenam a resposta privada.
- Registre horário, rota, regra acionada, volume e identificador interno da conta ou da exportação quando necessário. Use esses sinais para investigar extração em massa. Mantenha os registros com acesso restrito e prazo de retenção definido.

## 5. Documentar cópias identificadas

Use `/ai.txt` como aviso público e alinhe-o aos termos do site. Para um caso de cópia, reúna a URL original e a URL reproduzida, capturas com data, o release ou commit original e hashes dos arquivos relevantes. Identifique os trechos de código, textos ou elementos originais reproduzidos e os ativos cobertos por licença. Com esse material, encaminhe uma notificação documentada ao operador ou à plataforma responsável, conforme o caso.

O registro de programa de computador no INPI serve como evidência adicional de autoria ou titularidade. A proteção conferida pela Lei nº 9.609/1998 independe do registro. Métodos, ideias e conceitos matemáticos em si recebem o tratamento do art. 8º da Lei nº 9.610/1998. [Lei do Software](https://www.planalto.gov.br/ccivil_03/leis/l9609.htm) · [Lei de Direitos Autorais](https://www.planalto.gov.br/ccivil_03/leis/l9610.htm) · [INPI — registro de programa de computador](https://www.gov.br/inpi/pt-br/servicos/programas-de-computador/guia-basico)
