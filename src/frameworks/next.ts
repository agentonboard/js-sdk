// Re-exports the unified Web-Standard adapter without importing Next.js types,
// keeping the package free of framework dependencies (ADR-0002).
export {
  requireAgentAccount,
  type AgentAccountFailure,
  type AgentRequest,
  type RequireAgentAccountOptions,
  type RequireAgentAccountResult,
} from "./web.js";
