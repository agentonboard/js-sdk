export {
  normalizeAudience,
  verifyAgentToken,
  type VerifyAgentTokenOptions,
  type VerifyAgentTokenResult,
} from "./verify.js";

export { VERIFY_ERROR_DESCRIPTIONS, type VerifyErrorCode } from "./codes.js";

export {
  createAgentAccount,
  normalizeEmail,
  verifyAgentAccount,
  type AccountCreator,
  type AccountErrorCode,
  type AccountOutcome,
  type AccountResolver,
  type AgentIdentity,
  type CreateAccountOutcome,
  type CreateAgentAccountOptions,
  type VerifyAgentAccountOptions,
} from "./account.js";
