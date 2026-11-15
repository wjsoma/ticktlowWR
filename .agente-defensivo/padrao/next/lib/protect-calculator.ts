import 'server-only'

type Session = { userId: string }

type QuotaDecision =
  | { allowed: true }
  | { allowed: false; retryAfterSeconds: number }

type ExpectedError = { ok: false; status: 400 | 404 | 413 | 422; error: string }

type CalculationResult<Data> = { ok: true; data: Data } | ExpectedError

type ParseResult<Input> = { ok: true; input: Input } | ExpectedError

type CalculatorDependencies<Data, Input = Request> = {
  verifySession: (request: Request) => Promise<Session | null>
  canUseTool: (session: Session) => Promise<boolean>
  consumeQuota: (session: Session) => Promise<QuotaDecision>
  /**
   * Opcional. Valida tipo e tamanho da entrada ANTES de consumir quota, para que
   * requisições malformadas não gastem a cota do usuário nem cheguem ao cálculo.
   */
  parseInput?: (request: Request, session: Session) => Promise<ParseResult<Input>>
  calculate: (input: Input, session: Session) => Promise<CalculationResult<Data>>
  /**
   * Opcional. Origens aceitas em requisições que alteram estado com sessão por cookie
   * (ex.: ['https://fatyx.com.br']). Sem o cabeçalho Origin a requisição é recusada.
   */
  allowedOrigins?: string[]
  /** Opcional. Tamanho máximo do corpo declarado em Content-Length (padrão 64 KiB). */
  maxBodyBytes?: number
  /** Opcional. Recebe falhas inesperadas. Não registre payloads nem credenciais. */
  onError?: (error: unknown, context: { userId?: string; stage: string }) => void
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

function json(status: number, body: unknown, retryAfterSeconds?: number): Response {
  const headers = new Headers({
    'Cache-Control': 'private, no-store',
    'X-Robots-Tag': 'noindex',
    'X-Content-Type-Options': 'nosniff',
  })

  if (retryAfterSeconds !== undefined) {
    headers.set('Retry-After', String(retryAfterSeconds))
  }

  return Response.json(body, { status, headers })
}

export function protectCalculator<Data, Input = Request>(
  dependencies: CalculatorDependencies<Data, Input>,
) {
  const maxBodyBytes = dependencies.maxBodyBytes ?? 64 * 1024
  const allowedOrigins = dependencies.allowedOrigins?.map((origin) => origin.toLowerCase())

  return async function handleCalculation(request: Request): Promise<Response> {
    let stage = 'origin'
    let userId: string | undefined

    try {
      if (allowedOrigins && !SAFE_METHODS.has(request.method)) {
        const origin = request.headers.get('origin')?.toLowerCase()
        if (!origin || !allowedOrigins.includes(origin)) {
          return json(403, { error: 'origem_nao_permitida' })
        }
      }

      const declaredLength = Number(request.headers.get('content-length') ?? '0')
      if (!Number.isFinite(declaredLength) || declaredLength > maxBodyBytes) {
        return json(413, { error: 'entrada_muito_grande' })
      }

      stage = 'session'
      const session = await dependencies.verifySession(request)
      if (!session) return json(401, { error: 'sessao_necessaria' })
      userId = session.userId

      stage = 'authorization'
      const canUseTool = await dependencies.canUseTool(session)
      if (!canUseTool) return json(403, { error: 'acesso_restrito' })

      stage = 'parse'
      let input: Input
      if (dependencies.parseInput) {
        const parsed = await dependencies.parseInput(request, session)
        if (!parsed.ok) return json(parsed.status, { error: parsed.error })
        input = parsed.input
      } else {
        input = request as unknown as Input
      }

      stage = 'quota'
      const quota = await dependencies.consumeQuota(session)
      if (!quota.allowed) {
        const seconds = Number.isFinite(quota.retryAfterSeconds)
          ? Math.max(1, Math.ceil(quota.retryAfterSeconds))
          : 60

        return json(429, { error: 'limite_excedido' }, seconds)
      }

      stage = 'calculate'
      const result = await dependencies.calculate(input, session)
      if (!result.ok) return json(result.status, { error: result.error })

      return json(200, { data: result.data })
    } catch (error) {
      try {
        dependencies.onError?.(error, { userId, stage })
      } catch {
        // O registro nunca deve alterar a resposta.
      }
      return json(503, { error: 'temporariamente_indisponivel' })
    }
  }
}
