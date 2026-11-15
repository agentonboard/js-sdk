/**
 * How the verifier obtains the issuer's public signing keys.
 *
 * The SDK owns **no socket**. It never imports `node:net`, `node:http`, or `node:https`, never
 * binds a port, never holds a connection. It hands a URL to the host runtime's `fetch` and caches
 * the result, so the only requirement is that a `fetch` global exists — which is why the same code
 * runs unchanged on Cloudflare Workers, Deno, Bun, and in a browser. Supplying keys through `jwks`
 * or `fetchJwks` takes the network out of the picture entirely.
 *
 * The JWKS is untrusted remote input: it is shape-checked before anything is cached from it, and a
 * set that fails the check is a failed fetch, never a bad token. Keys are the only thing this
 * process keeps. Verification results are never cached — a cached "this token is valid" is how a
 * revoked token keeps working.
 *
 * A failed fetch is not a failed verification. jose 6.2.12 serves its cached set only while it is
 * fresh, so past `cacheMaxAge` a blip on the key endpoint rejects every request even though a good
 * set is still in memory. This module keeps its own copy of the last set that passed validation and
 * verifies against that instead, so a bad minute on the key endpoint costs availability rather than
 * authentication.
 *
 * Three of this module's guarantees are properties of jose's internals rather than of its
 * documented API, so a `jose` minor release is a change to our security behaviour and has to be
 * re-checked against the tests rather than only against the build: the remote-set contract this
 * module is built on (a stale set stops being served, and a fetch failure rejects instead of falling
 * back), `isUsableJWK`'s `kid` matching — a published key carrying no `kid` matches *any* request,
 * which is why {@link isUsableKeyEntry} refuses one — and `minRsaBits`, mirrored by
 * {@link assertUsableSigningKey}. Each is named at the line that depends on it, so a bump to `jose`
 * has a place to be checked.
 */

import {
  createLocalJWKSet,
  createRemoteJWKSet,
  customFetch,
  errors,
  type CryptoKey,
  type FlattenedJWSInput,
  type JSONWebKeySet,
  type JWSHeaderParameters,
  type JWTVerifyGetKey,
  type LocalJWKSet,
  type RemoteJWKSet,
} from "jose";

/**
 * The most distinct key sources one process will hold at once. Almost every deployment has exactly
 * one issuer, so eight is generous; the bound is what stops a caller who varies the JWKS URL per
 * tenant from growing this process's state for as long as it lives
 * (docs/adr/0002-sdk-runtime-contract-and-framework-subpaths.md, Decision 2).
 * It is not configurable, because there is no tuning question here.
 */
const MAX_CACHED_KEY_SOURCES = 8;

/** How long after a successful fetch an unmatched `kid` may cause another one. */
const COOLDOWN_DURATION_MS = 30000;

/** How long a fetched set is served before a refetch is due. */
const CACHE_MAX_AGE_MS = 3600000;

const BASE64URL = /^[A-Za-z0-9_-]+$/;

/**
 * A key set we could not obtain. Distinct from a token we could not verify: a Relying Party must be able
 * to tell "our JWKS endpoint is down" from "someone forged a token".
 *
 * Every message on this class is written in this file. A value thrown by a retriever never becomes
 * one: a `fetch` rejection and a Relying Party's own `fetchJwks` routinely carry a connection string
 * (`postgres://user:pw@db.internal:5432`), and this string is published in a 401 body that
 * whoever made the request can read. `AGENTS.md`: a secret never appears in an error. The detail
 * belongs in the retriever's own log, which is what {@link KeyResolverOptions.fetchJwks} says to do
 * with it. `account.ts` sets the same rule for a thrown account resolver.
 */
export class KeySourceUnavailableError extends Error {}

export interface KeyResolverOptions {
  /**
   * Where the set lives. Ignored when `jwks` is supplied, which touches no network at all.
   */
  url: URL;

  /**
   * A parsed key set to use instead of fetching one. Bypasses the URL entirely and still goes
   * through {@link assertJwkSet}: a broken set is our bug or an outage, not the caller's token.
   */
  jwks?: JSONWebKeySet;

  /**
   * Replaces the host runtime's `fetch` for retrieving the set. Bypasses the default retriever but
   * not the shape check, and is subject to the same last-known-good behaviour on failure.
   *
   * **Log anything you throw here, inside your own retriever.** The value is not reported onward: a
   * failure reaches the caller as `KEY_SOURCE_UNAVAILABLE` with a message this package wrote, so a
   * connection string, a URL with userinfo, or a credential in a header is yours alone to log.
   */
  fetchJwks?: (url: string) => Promise<unknown>;
}

/** A retriever that replaces the default one, identified by the caller so a swap is visible. */
type FetchJwks = (url: string) => Promise<unknown>;

/** The default retriever, which additionally forwards jose's timeout signal to the host `fetch`. */
type Retriever = (url: string, init: RequestInit) => Promise<unknown>;

/**
 * jose resolves a public key, never a secret, from a JWK Set — so never anything else. Spelled out
 * rather than reusing `JWTVerifyGetKey`, whose return type is widened to accept every `KeyInput`.
 */
type SigningKeyResolver = (
  protectedHeader?: JWSHeaderParameters,
  token?: FlattenedJWSInput
) => Promise<CryptoKey>;

/**
 * Reports a key-selection failure as-is — the set was fine, the token named no key in it — and
 * everything else as an outage, so `verify.ts` never has to tell a bad token from a bad endpoint.
 *
 * The ambiguous-set case is named rather than summarised. A JWKS publishing one `kid` twice is a
 * misconfiguration with a security meaning — "which of these two do I trust?" — and it is the
 * theirs to fix. Reported as a bare outage it sends them looking for an endpoint that is up.
 *
 * Everything else loses its message: the only remaining values are a retriever's and a runtime's,
 * and neither is ours to publish (see {@link KeySourceUnavailableError}).
 */
function rethrowAsKeySourceFailure(err: unknown): never {
  if (err instanceof errors.JWKSNoMatchingKey) throw err;
  if (err instanceof KeySourceUnavailableError) throw err;
  if (err instanceof errors.JWKSMultipleMatchingKeys) {
    throw new KeySourceUnavailableError(
      "the JWKS published more than one usable key for the token's kid, so no single signing key can be selected"
    );
  }
  throw new KeySourceUnavailableError(
    "the key set could not be obtained, and this SDK does not report the error that stopped it"
  );
}

/**
 * jose refuses an RSA key under 2048 bits inside its own verify path, after the resolver has
 * returned, where the failure is a raw `TypeError` that reaches the Relying Party as `MALFORMED_TOKEN` —
 * our misconfiguration reported as their malformed token. A set we cannot verify anything with is an
 * outage, so it is caught where we still know where it came from.
 *
 * The 2048 here mirrors jose's own `minRsaBits` for RS256, and has to be re-checked when `jose` is
 * bumped: raise it and this check rejects keys jose would still accept, lower it and a key jose
 * refuses reaches the verifier as a `TypeError` and is reported as `MALFORMED_TOKEN` again.
 */
function assertUsableSigningKey(key: CryptoKey): CryptoKey {
  const { modulusLength } = key.algorithm as { modulusLength?: number };
  if (typeof modulusLength === "number" && modulusLength < 2048) {
    throw new KeySourceUnavailableError(
      `JWKS key is RSA ${modulusLength}-bit; this SDK verifies RS256 at 2048 bits or larger`
    );
  }
  return key;
}

async function keyFrom(
  resolve: SigningKeyResolver,
  protectedHeader: Parameters<SigningKeyResolver>[0],
  token: Parameters<SigningKeyResolver>[1]
): Promise<CryptoKey> {
  try {
    return assertUsableSigningKey(await resolve(protectedHeader, token));
  } catch (err) {
    rethrowAsKeySourceFailure(err);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isBase64UrlString(value: unknown): value is string {
  return typeof value === "string" && value !== "" && BASE64URL.test(value);
}

function isUsableKeyEntry(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (typeof value.kid !== "string" || value.kid === "") return false;
  if (typeof value.kty !== "string" || value.kty === "") return false;
  // Only an RSA key can verify the RS256 tokens this SDK accepts, so only an RSA key is held to the
  // RSA shape. A set that also publishes an EC or OKP key for some other purpose stays usable.
  if (value.kty !== "RSA") return true;
  return isBase64UrlString(value.n) && isBase64UrlString(value.e);
}

/**
 * The check `AGENTS.md` asks for on untrusted remote input. jose's own gate accepts any array of
 * objects under `keys`, which would hand a JSON array or a key with no modulus to the import path.
 */
function assertJwkSet(value: unknown): JSONWebKeySet {
  if (!isRecord(value) || !Array.isArray(value.keys) || !value.keys.every(isUsableKeyEntry)) {
    throw new KeySourceUnavailableError(
      "JWKS is not a { keys: [...] } set of usable key entries"
    );
  }
  // Rebuilt rather than passed through, so nothing an endpoint sent beyond the keys survives.
  return { keys: [...value.keys] };
}

async function retrieveOverGlobalFetch(url: string, init: RequestInit): Promise<unknown> {
  const response = await fetch(url, init);
  if (response.status !== 200) {
    // Ours, not the runtime's: the status is the diagnosis, and a message this file wrote is safe
    // to publish. A `fetch` *rejection* is not, and is never interpolated anywhere.
    throw new KeySourceUnavailableError(
      `JWKS endpoint responded ${response.status} ${response.statusText}`
    );
  }
  return await response.json();
}

/**
 * A resolver over a set the caller handed us. Nothing is fetched, so the only way to fail is a set
 * that does not survive the shape check — which is reported on every call, not cached as a verdict.
 */
function suppliedKeySource(supplied: unknown): SigningKeyResolver {
  let resolve: SigningKeyResolver | undefined;
  return async (protectedHeader, token) => {
    resolve ??= createLocalJWKSet(assertJwkSet(supplied));
    return keyFrom(resolve, protectedHeader, token);
  };
}

/**
 * A resolver over a URL, with the last-known-good fallback jose does not provide.
 *
 * The set this module holds is written only from a fetch that passed {@link assertJwkSet}, and only
 * ever by {@link remember}, so "last known good" means what it says: a set that was fetched and
 * checked. jose keeps its own copy for the same purpose, but only consults it while fresh, which is
 * the gap this closes.
 */
function remoteKeySource(url: URL, retrieve: Retriever): SigningKeyResolver {
  let lastKnownGood: JSONWebKeySet | undefined;
  let lastKnownGoodResolver: LocalJWKSet | undefined;

  const remember = (set: JSONWebKeySet) => {
    lastKnownGood = set;
    lastKnownGoodResolver = undefined;
  };

  const remote: RemoteJWKSet = createRemoteJWKSet(url, {
    cooldownDuration: COOLDOWN_DURATION_MS,
    cacheMaxAge: CACHE_MAX_AGE_MS,
    [customFetch]: async (href, init) => {
      const set = assertJwkSet(await retrieve(href, init));
      remember(set);
      return new Response(JSON.stringify(set), {
        headers: { "content-type": "application/json" },
      });
    },
  });

  return async (protectedHeader, token) => {
    try {
      return await keyFrom(remote, protectedHeader, token);
    } catch (err) {
      if (err instanceof errors.JWKSNoMatchingKey) throw err;
      if (!lastKnownGood) {
        // Published as-is: `keyFrom` has already turned anything untrusted into a message this file
        // wrote, so this is a diagnosis and not a value from the retriever.
        throw err;
      }
      try {
        lastKnownGoodResolver ??= createLocalJWKSet(lastKnownGood);
        return await keyFrom(lastKnownGoodResolver, protectedHeader, token);
      } catch (fallbackErr) {
        rethrowAsKeySourceFailure(fallbackErr);
      }
    }
  };
}

/**
 * A remote key source is identified by its URL, not by its retriever: two URLs behind one
 * `fetchJwks` are two issuers and must not share a set. The retriever travels with the entry so a
 * caller who swaps one mid-process does not keep the resolver built around the old one.
 */
interface CachedKeySource {
  retrieve: FetchJwks | undefined;
  resolve: SigningKeyResolver;
}

const keySourceCache = new Map<string | object, CachedKeySource>();

function cachedKeySource(
  key: string | object,
  retrieve: FetchJwks | undefined,
  create: () => SigningKeyResolver
): SigningKeyResolver {
  const cached = keySourceCache.get(key);
  if (cached && cached.retrieve === retrieve) {
    // A Map iterates in insertion order, so re-inserting is what makes this least-recently-used.
    keySourceCache.delete(key);
    keySourceCache.set(key, cached);
    return cached.resolve;
  }

  const created: CachedKeySource = { retrieve, resolve: create() };
  keySourceCache.set(key, created);
  if (keySourceCache.size > MAX_CACHED_KEY_SOURCES) {
    const [leastRecentlyUsed] = keySourceCache.keys();
    if (leastRecentlyUsed !== undefined) keySourceCache.delete(leastRecentlyUsed);
  }
  return created.resolve;
}

/**
 * The one place a verification's key source is built, so the "no socket", bounded-state, and
 * last-known-good guarantees are stated once and cannot be bypassed by a caller.
 *
 * A supplied `jwks` bypasses the URL entirely and wins over `fetchJwks`: supplying keys is the
 * stronger statement, and it is the only path that touches no network at all.
 */
export function getKeyResolver(options: KeyResolverOptions): JWTVerifyGetKey {
  const { jwks, fetchJwks, url } = options;

  if (jwks !== undefined) {
    return cachedKeySource(jwks, undefined, () => suppliedKeySource(jwks));
  }

  return cachedKeySource(url.href, fetchJwks, () =>
    remoteKeySource(url, fetchJwks ? (href) => fetchJwks(href) : retrieveOverGlobalFetch)
  );
}
