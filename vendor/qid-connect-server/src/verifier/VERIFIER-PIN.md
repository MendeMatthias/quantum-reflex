# Frozen verifier, do not edit

`btx-ownership-verify.js` in this folder is a byte-for-byte copy of the frozen
qID Sign-In v1 reference verifier delivered in the `qID-signin-v1` package on
2026-07-07. The v1 proof format is frozen. New capability means a new version,
never a mutation of this file.

```
sha256(btx-ownership-verify.js) = 0eeeec62383b63013283de52338cd6915e2fab638fc8988ad99640166b3a23b0
sha256(../../test-vectors/vectors.json) = a7d8d6bf5322d09f6f3f06d2a876285c9fdfd48ca8ad4377ab47f4a61b70be38
```

The test suite recomputes the file hash and fails if it changes, and runs the
full v1 test vector set against it. If you need different behavior, wrap it in
`core.js`. Do not touch this file.
