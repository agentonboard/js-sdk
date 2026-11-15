/**
 * Every failure `verifyAgentToken` can report.
 *
 * Published vocabulary: codes are only ever added, never renamed or removed, because Relying Parties
 * branch on them. Keep this union short — every code is a decision each future language SDK has
 * to make identically (docs/adr/0002-sdk-runtime-contract-and-framework-subpaths.md,
 * Decision 4).
 */
export type VerifyErrorCode =
  | "EXPIRED"
  | "INVALID_SIGNATURE"
  | "AUDIENCE_MISMATCH"
  | "ISSUER_MISMATCH"
  | "MALFORMED_TOKEN"
  | "CONFIG_ERROR"
  | "UNKNOWN_KEY"
  | "KEY_SOURCE_UNAVAILABLE"
  | "MISSING_EMAIL";

/**
 * One line per code, for a Relying Party reading a failure at 2am. A wrong `error` string costs a support
 * ticket; a wrong `code` costs a security bug.
 */
export const VERIFY_ERROR_DESCRIPTIONS = Object.freeze({
  EXPIRED: "The token's exp claim is in the past, beyond the clock-skew tolerance.",
  INVALID_SIGNATURE:
    "The signature did not verify against a published key, or the token used an algorithm this SDK does not accept.",
  AUDIENCE_MISMATCH: "The token was minted for a different audience, or carries no aud claim.",
  ISSUER_MISMATCH: "The token was minted by a different issuer, or carries no iss claim.",
  MALFORMED_TOKEN:
    "The token is not a readable JWT, or a claim this SDK requires is absent or unusable.",
  CONFIG_ERROR:
    "The call itself is wrong: audience, issuer, JWKS URL, or clock-skew tolerance.",
  UNKNOWN_KEY:
    "The token's kid matched no key in the key set this SDK could obtain. The code does not say why: the key may be revoked or rotated away, the token may be forged, or the key endpoint may be unreachable and leave this SDK holding an out-of-date set.",
  KEY_SOURCE_UNAVAILABLE:
    "This SDK could not obtain a signing key: the key set could not be fetched, the published set is not one this SDK can verify against, or it publishes more than one key for the token's kid.",
  MISSING_EMAIL: "The token verified but carries no usable email claim to identify the human.",
} as const satisfies Record<VerifyErrorCode, string>);
