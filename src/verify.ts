import {
  decodeProtectedHeader,
  errors,
  jwtVerify,
  type JSONWebKeySet,
} from "jose";

import type { VerifyErrorCode } from "./codes.js";
import { getKeyResolver, KeySourceUnavailableError } from "./keys.js";

export interface VerifyAgentTokenOptions {
  /**
   * The raw JWT token string extracted from the Authorization: Bearer <token> header.
   */
  token: string;

  /**
   * The expected target domain (audience) for this service (e.g. "notes.com" or "api.notes.com").
   */
  audience: string;

  /**
   * The expected "iss" claim, and the base for the default JWKS URL.
   * Defaults to process.env.AON_ISSUER or "https://agentonboard.xyz".
   */
  issuer?: string;

  /**
   * Optional custom JWKS URL. Defaults to `${issuer}/.well-known/jwks.json`.
   *
   * Ignored when `jwks` is supplied.
   */
  jwksUrl?: string;

  /**
   * A parsed JWKS to verify against, instead of fetching one. No URL is used and no request is
   * made — the keys are the ones the caller pinned. The set is still shape-checked, so a set this
   * SDK cannot use is reported as `KEY_SOURCE_UNAVAILABLE` rather than blamed on the token.
   *
   * This is how an air-gapped or self-hosted issuer works, and how a cross-language test vector
   * supplies keys without a network.
   */
  jwks?: JSONWebKeySet;

  /**
   * Replaces the host runtime's `fetch` for retrieving the JWKS. Called with the same URL that
   * would have been fetched, and expected to resolve to a parsed JWKS. Useful where the default
   * `fetch` is not the one you want — a pinned egress proxy, a cached copy, a test with no network.
   *
   * **Log anything you throw here, inside your own retriever.** The value is never reported onward:
   * a failure reaches the caller as `KEY_SOURCE_UNAVAILABLE` carrying a message this SDK wrote, so
   * a connection string or a URL with credentials in it stays yours to log rather than landing in
   * your error aggregator.
   *
   * Ignored when `jwks` is supplied.
   */
  fetchJwks?: (url: string) => Promise<unknown>;

  /**
   * Seconds of clock skew tolerated on the "exp" claim. Defaults to 5.
   */
  clockToleranceSeconds?: number;
}

export type VerifyAgentTokenResult =
  | {
      readonly ok: true;
      readonly email: string;
      readonly sub: string;
      /** @deprecated Alias for `sub`. Contains the subject claim (verified email); use `sub` or `email` instead. */
      readonly userId?: string;
      readonly expiresAt: number;
      readonly jti: string;
      readonly audience: string;
    }
  | {
      readonly ok: false;
      readonly code: VerifyErrorCode;
      readonly error: string;
    };

const ALGORITHMS = ["RS256"];
const REQUIRED_CLAIMS = ["exp", "jti", "sub", "email"];
const DEFAULT_CLOCK_TOLERANCE_SECONDS = 5;

/**
 * Normalizes audience input into a clean hostname (e.g. "https://api.notes.com/v1" -> "api.notes.com").
 */
export function normalizeAudience(input: string): string {
  if (!input) return "";
  const raw = input.trim().replace(/\/+$/, "");
  try {
    const url = new URL(raw.includes("://") ? raw : `http://${raw}`);
    const host = url.hostname.toLowerCase();
    if (!host) return "";
    if ((host === "localhost" || host === "127.0.0.1") && url.port) {
      return `${host}:${url.port}`;
    }
    return host;
  } catch {
    return "";
  }
}

/**
 * The single place the expected issuer is resolved, so the "iss" claim check and the JWKS URL can
 * never disagree.
 */
function resolveIssuer(issuer?: string): string {
  return (
    issuer ||
    (typeof process !== "undefined" && process.env?.AON_ISSUER) ||
    "https://agentonboard.xyz"
  );
}

/**
 * Verifies an AgentOnboard Agent Identity Token against public JWKS.
 *
 * This function guarantees safety: it NEVER throws unhandled runtime exceptions.
 */
export async function verifyAgentToken(
  options: VerifyAgentTokenOptions
): Promise<VerifyAgentTokenResult> {
  const { token, audience } = options;

  if (!token || typeof token !== "string") {
    return {
      ok: false,
      error: "Missing or empty token",
      code: "MALFORMED_TOKEN",
    };
  }

  if (!audience || typeof audience !== "string") {
    return {
      ok: false,
      error: "Missing expected audience for verification",
      code: "CONFIG_ERROR",
    };
  }

  const clockTolerance =
    options.clockToleranceSeconds ?? DEFAULT_CLOCK_TOLERANCE_SECONDS;
  if (!Number.isFinite(clockTolerance) || clockTolerance < 0) {
    return {
      ok: false,
      error: "clockToleranceSeconds must be a non-negative number of seconds",
      code: "CONFIG_ERROR",
    };
  }

  const cleanToken = token.replace(/^Bearer\s+/i, "").trim();
  const normalizedAudience = normalizeAudience(audience);

  if (!normalizedAudience) {
    return {
      ok: false,
      error: `Audience does not normalize to a hostname: "${audience}"`,
      code: "CONFIG_ERROR",
    };
  }

  const issuer = resolveIssuer(options.issuer);
  const jwksUrl = options.jwksUrl || `${issuer.replace(/\/+$/, "")}/.well-known/jwks.json`;

  let jwksEndpoint: URL;
  try {
    jwksEndpoint = new URL(jwksUrl);
  } catch {
    return {
      ok: false,
      error: `JWKS URL is not a valid URL: "${jwksUrl}"`,
      code: "CONFIG_ERROR",
    };
  }

  try {
    const { kid } = decodeProtectedHeader(cleanToken);
    if (typeof kid !== "string" || !kid) {
      return {
        ok: false,
        error: "Token header carries no kid, so no signing key can be selected",
        code: "UNKNOWN_KEY",
      };
    }
  } catch {
    return {
      ok: false,
      error: "Token is not a readable compact JWS",
      code: "MALFORMED_TOKEN",
    };
  }

  try {
    const { payload } = await jwtVerify(
      cleanToken,
      getKeyResolver({
        url: jwksEndpoint,
        jwks: options.jwks,
        fetchJwks: options.fetchJwks,
      }),
      {
        audience: normalizedAudience,
        issuer,
        algorithms: ALGORITHMS,
        requiredClaims: REQUIRED_CLAIMS,
        clockTolerance,
      }
    );

    const email = typeof payload.email === "string" ? payload.email : undefined;
    if (!email) {
      return {
        ok: false,
        error: "Token carries no usable email claim",
        code: "MISSING_EMAIL",
      };
    }

    const sub = typeof payload.sub === "string" ? payload.sub : email;
    const expiresAt = typeof payload.exp === "number" ? payload.exp : 0;
    const jti = typeof payload.jti === "string" ? payload.jti : "";

    return {
      ok: true,
      email,
      sub,
      userId: sub,
      expiresAt,
      jti,
      audience: normalizedAudience,
    };
  } catch (err: unknown) {
    if (err instanceof KeySourceUnavailableError) {
      return {
        ok: false,
        error: `Could not obtain a signing key: ${err.message}`,
        code: "KEY_SOURCE_UNAVAILABLE",
      };
    }

    if (err instanceof errors.JWTExpired) {
      return {
        ok: false,
        error: "Agent Identity Token has expired (5-minute lifetime exceeded)",
        code: "EXPIRED",
      };
    }

    if (err instanceof errors.JWTClaimValidationFailed) {
      if (err.claim === "aud") {
        return {
          ok: false,
          error: `Audience mismatch: token was minted for different domain (${err.message})`,
          code: "AUDIENCE_MISMATCH",
        };
      }
      if (err.claim === "iss") {
        return {
          ok: false,
          error: "Issuer mismatch",
          code: "ISSUER_MISMATCH",
        };
      }
      if (err.claim === "email") {
        return {
          ok: false,
          error: "Token carries no usable email claim",
          code: "MISSING_EMAIL",
        };
      }
    }

    if (err instanceof errors.JWSSignatureVerificationFailed) {
      return {
        ok: false,
        error: "Invalid cryptographic signature",
        code: "INVALID_SIGNATURE",
      };
    }

    if (err instanceof errors.JOSEAlgNotAllowed || err instanceof errors.JOSENotSupported) {
      return {
        ok: false,
        error: "Token uses a signing algorithm this SDK does not accept",
        code: "INVALID_SIGNATURE",
      };
    }

    // `JWKSMultipleMatchingKeys` is absent on purpose: the key resolver converts it to a key-source
    // failure, so it is answered above and can never arrive here. Reported as an unknown key it
    // would send a Relying Party hunting for a forgery their JWKS caused.
    if (err instanceof errors.JWKSNoMatchingKey) {
      return {
        ok: false,
        // One string for two situations: the current set does not carry this kid, or the set could
        // not be refreshed and the last one held does not. Neither is knowable from here, so the
        // message says so rather than implying the token was forged.
        error:
          "Token kid matched no key in the key set this SDK could obtain. The set may be out of date when the key endpoint is unreachable, so this does not mean the token is forged.",
        code: "UNKNOWN_KEY",
      };
    }

    const message = err instanceof Error ? err.message : "Unknown token verification error";
    return {
      ok: false,
      error: message,
      code: "MALFORMED_TOKEN",
    };
  }
}

/**
 * @deprecated Use {@link verifyAgentToken}. It returns the failure `code` and the verified `jti`,
 * `expiresAt`, and `userId` that this shim drops, so a Relying Party cannot tell a revoked key from a
 * typo.
 */
export async function verifyToken(options: {
  token: string;
  audience: string;
}): Promise<{ ok: boolean; email?: string; error?: string }> {
  const res = await verifyAgentToken(options);
  if (res.ok) {
    return { ok: true, email: res.email };
  }
  return { ok: false, error: res.error };
}
