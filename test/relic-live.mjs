// Tests for the relic-name resolver. The pure decode runs offline; the live
// section hits real btxscan data and is skipped (not failed) when offline.
//
//   bun test/relic-live.mjs
//
// SPDX-License-Identifier: MIT
import { nameFromCommitment, sanitizeName, fetchRelicNames } from "../lib/relic-name.mjs";

let passed = 0, failed = 0, skipped = 0;
const ok = (c, l) => (c ? (passed++, console.log("  ✓ " + l)) : (failed++, console.log("  ✗ " + l)));

console.log("nameFromCommitment (schema-2 name-on-chain, pure)");
// 05 "happy" + zero pad  ->  "happy"
ok(nameFromCommitment("0568617070790000000000000000000000000000000000000000000000000000") === "happy", "decodes 'happy'");
// a real sha256 commitment is not a valid length-prefixed name
ok(nameFromCommitment("b295be93ee02c77c73ccad6aa1a75f8bcae8e609f6214e7b54ce3ffa95d8b93b") === null, "hash commitment -> null");
ok(nameFromCommitment("00".repeat(32)) === null, "zero-length -> null");
ok(nameFromCommitment("ff".repeat(32)) === null, "len 255 out of range -> null");
ok(nameFromCommitment("046a6f686e".padEnd(64, "0")) === "john", "decodes 'john'"); // 04 'john' + pad
ok(nameFromCommitment("notvalidhex") === null, "non-hex -> null");

console.log("\nsanitizeName");
ok(sanitizeName("  Bob  ") === "Bob", "trims");
ok(sanitizeName("<script>x") === "scriptx", "strips angle brackets");
ok(sanitizeName("z".repeat(40)).length === 32, "caps at 32");
ok(sanitizeName("   ") === null, "whitespace-only -> null");

console.log("\nlive: fetchRelicNames against real btxscan holders");
try {
  const health = await fetch("https://btxscan.io/api/relics/holder?address=btx1zh28h2rye67ca95wl9gzn9ar0ffp249fujenf6mjsmul8luwg306qz35krz", {
    signal: AbortSignal.timeout(12000),
  });
  if (!health.ok) throw new Error("holder API not ok: " + health.status);

  // Attribute Archive holder -> schema-2 name-on-chain "happy"
  const attr = await fetchRelicNames("btx1zh28h2rye67ca95wl9gzn9ar0ffp249fujenf6mjsmul8luwg306qz35krz", { timeoutMs: 12000 });
  ok(attr.some((r) => r.name === "happy" && r.schema === 2), `ATTRIBUT holder resolves 'happy' (${JSON.stringify(attr)})`);

  // Last Relic holder -> schema-0 engraving "wombatcow"
  const final = await fetchRelicNames("btx1zcpsa3m9z9jf049lmyzrskz7e73xt08rk8z95shtxp3a6ukdea22sd5trz5", { timeoutMs: 12000 });
  ok(final.some((r) => r.name === "wombatcow" && r.schema === 0), `FINALOG1 holder resolves 'wombatcow' (${JSON.stringify(final)})`);

  // An address that holds nothing -> []
  const none = await fetchRelicNames("btx1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqjkq4nq", { timeoutMs: 12000 });
  ok(Array.isArray(none), "empty/invalid holder -> array (no throw)");
} catch (e) {
  skipped += 2;
  console.log("  ~ SKIPPED live checks (offline or btxscan unreachable): " + e.message);
}

console.log(`\n${passed} passed, ${failed} failed, ${skipped} skipped`);
process.exit(failed ? 1 : 0);
