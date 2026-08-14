/**
 * JWKS 本地验签（支持 kid 双钥）。
 * 依赖 Web Crypto；适用于浏览器 / Node19+。
 */
export type AccessClaims = {
  uid: string;
  cid: string;
  tid: string;
  roles?: string[];
  scope?: string;
  iss?: string;
  exp?: number;
  sub?: string;
  jti?: string;
};

type JWK = JsonWebKey & { kid?: string; alg?: string; kty: string };

type JWKS = { keys: JWK[] };

function b64urlToBuf(s: string): ArrayBuffer {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function parseJWT(token: string): { header: any; payload: any; data: Uint8Array; sig: ArrayBuffer } {
  const [h, p, s] = token.split(".");
  if (!h || !p || !s) throw new Error("malformed jwt");
  const header = JSON.parse(new TextDecoder().decode(b64urlToBuf(h)));
  const payload = JSON.parse(new TextDecoder().decode(b64urlToBuf(p)));
  const data = new TextEncoder().encode(`${h}.${p}`);
  return { header, payload, data, sig: b64urlToBuf(s) };
}

export class JWKSVerifier {
  private cache: JWKS | null = null;
  private fetchedAt = 0;

  constructor(
    private jwksURL: string,
    private issuer = "",
    private cacheTTLMs = 5 * 60 * 1000,
  ) {}

  async refresh(): Promise<void> {
    const res = await fetch(this.jwksURL);
    if (!res.ok) throw new Error(`jwks http ${res.status}`);
    this.cache = (await res.json()) as JWKS;
    this.fetchedAt = Date.now();
  }

  private async keys(): Promise<JWK[]> {
    if (!this.cache || Date.now() - this.fetchedAt > this.cacheTTLMs) {
      await this.refresh();
    }
    return this.cache?.keys || [];
  }

  async verify(token: string): Promise<AccessClaims> {
    const { header, payload, data, sig } = parseJWT(token);
    if (header.alg !== "RS256") throw new Error("unexpected alg");
    if (this.issuer && payload.iss && payload.iss !== this.issuer) {
      throw new Error("issuer mismatch");
    }
    if (payload.exp && payload.exp * 1000 < Date.now()) {
      throw new Error("token expired");
    }
    const keys = await this.keys();
    let jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk && !header.kid) jwk = keys[0];
    if (!jwk) throw new Error(`unknown kid ${header.kid}`);
    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sig, data);
    if (!ok) throw new Error("bad signature");
    return payload as AccessClaims;
  }
}
