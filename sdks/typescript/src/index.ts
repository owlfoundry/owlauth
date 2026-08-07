export const VERSION = "0.0.0-dev";

export { Client, type BeginLoginOptions, type ClientOptions, type CryptoProvider } from "./client.js";
export {
  OwlAuthError,
  type CallerAction,
  type ClientErrorOptions,
  type ErrorCategory,
  type RetryDisposition,
} from "./errors.js";
export {
  AccessToken,
  type BrowserLogoutPreparation,
  CredentialPair,
  type CredentialPairRecord,
  type CurrentUser,
  type LoginStartResult,
  type OperationOptions,
  PendingLogin,
  type PendingLoginRecord,
  type ProjectJwks,
  type PublicApplicationConfiguration,
  type PublicJwk,
  type PublicProvider,
  type UserProjection,
  ValidatedCallback,
} from "./types.js";
