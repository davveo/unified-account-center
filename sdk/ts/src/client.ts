export type AuthClientOptions = {
  endpoint: string;
  clientId: string;
  clientSecret?: string;
  fetch?: typeof fetch;
};

type ApiBody<T> = {
  code: number;
  message: string;
  request_id?: string;
  data?: T;
};

export class AuthClient {
  private endpoint: string;
  private clientId: string;
  private clientSecret?: string;
  private fetchImpl: typeof fetch;

  constructor(opts: AuthClientOptions) {
    this.endpoint = opts.endpoint.replace(/\/$/, "");
    this.clientId = opts.clientId;
    this.clientSecret = opts.clientSecret;
    this.fetchImpl = opts.fetch ?? fetch;
  }

  private async request<T>(path: string, init: RequestInit & { requireSecret?: boolean } = {}): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-Client-Id": this.clientId,
      ...(init.headers as Record<string, string> | undefined),
    };
    if (init.requireSecret && this.clientSecret) {
      headers["X-Client-Secret"] = this.clientSecret;
    }
    const res = await this.fetchImpl(`${this.endpoint}${path}`, { ...init, headers });
    const body = (await res.json()) as ApiBody<T>;
    if (body.code !== 0) {
      throw new Error(body.message || `auth error ${body.code}`);
    }
    return body.data as T;
  }

  listMethods() {
    return this.request<{ methods: string[] }>("/api/v1/auth/methods");
  }

  challenge(input: { method: string; identity: string; scene?: string; captcha_token?: string }) {
    return this.request<{
      challenge_id: string;
      expire_in: number;
      resend_after: number;
      masked_target: string;
    }>("/api/v1/auth/challenge", { method: "POST", body: JSON.stringify(input) });
  }

  login(input: Record<string, unknown>) {
    return this.request<Record<string, unknown>>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  refresh(refreshToken: string) {
    return this.request<Record<string, unknown>>("/api/v1/auth/token/refresh", {
      method: "POST",
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
  }

  introspect(token: string) {
    return this.request<Record<string, unknown>>("/api/v1/auth/introspect", {
      method: "POST",
      body: JSON.stringify({ token }),
      requireSecret: true,
    });
  }

  jwks() {
    return this.fetchImpl(`${this.endpoint}/.well-known/jwks.json`).then((r) => r.json());
  }

  stepUp(accessToken: string, input: Record<string, unknown>) {
    return this.request<Record<string, unknown>>("/api/v1/auth/step-up", {
      method: "POST",
      body: JSON.stringify(input),
      headers: { Authorization: `Bearer ${accessToken}` },
    });
  }
}
