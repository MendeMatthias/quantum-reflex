# Vendored: @qid/connect-server

This directory is a **verbatim copy** of `packages/server` from the
[qid-connect](../../../qid-connect) monorepo, pinned at:

    @qid/connect-server  v1.6.4

It is vendored (not forked) so Quantum Reflex deploys as a single self-contained
project without needing the qID Connect monorepo workspace on the box. The qID
Sign-In protocol is **frozen v1** and the verifier is never modified.

## Rules
- **Do not edit anything in `src/`.** This is a consumer copy, not a fork.
- To update, re-copy from upstream and bump the version above:

      cp -R ../../qid-connect/packages/server/src ./src
      cp ../../qid-connect/packages/server/package.json ./package.json

- Runtime deps (`@noble/post-quantum`, `@noble/hashes`, `@scure/base`) are
  declared in the **root** `package.json` and resolve from the project's
  `node_modules`. Keep those versions matched to `./package.json`.

The game imports it by relative path:

    import { createQidConnect, SqliteNonceStore, SqliteAccounts } from "./vendor/qid-connect-server/src/index.js";
    import { qidMiddleware, requireQidSession } from "./vendor/qid-connect-server/src/middleware.js";
