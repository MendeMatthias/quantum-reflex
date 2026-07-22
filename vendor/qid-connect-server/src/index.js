// @qid/connect-server
//
// qID Connect server SDK. The address is the account: a user proves control
// of their BTX address with a post-quantum signature and that address IS
// their identity in your app. No email, no password.
//
// SPDX-License-Identifier: MIT

export { createQidConnect } from "./core.js";
export { qidMiddleware, requireQidSession } from "./middleware.js";
export { qidNextHandlers, getQidSession } from "./next.js";
export { IssuedNonceStore, MemoryAccounts } from "./stores.js";
export { SqliteNonceStore, SqliteAccounts } from "./sqlite.js";
export { signSession, verifySessionToken } from "./session.js";

// The frozen qID Sign-In v1 reference verifier, re-exported for apps that
// want the primitives directly. Never modified here, see verifier/VERIFIER-PIN.md.
export {
  verifySignIn,
  verifyOwnership,
  makeChallenge,
  challengeBytes,
  canonicalChallengeJSON,
  deriveAddress,
  CONSTANTS,
  POLICY_DEFAULTS,
} from "./verifier/btx-ownership-verify.js";
