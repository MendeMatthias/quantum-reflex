// relic-name.mjs — given a BTX address, find the NAME the holder forged into a
// relic they currently hold, so Quantum Reflex can offer it as their board name.
//
// Two on-chain name mechanisms (verified against live btxscan data):
//   schema 2  Attribute Archive ("the human layer"): the 32 commitment bytes ARE
//             the name — [len(1)][utf8][zero-pad]. Decoded locally, no network.
//   schema 0  Last Relic (FINALOG1) / Genesis: the forged name is the `engraving`
//             in the off-chain record, fetched by commitment from btxscan.
//
// Held relics + commitments come from the public, CORS-open holder scan:
//   GET {base}/api/relics/holder?address=btx1…   (the "gate a perk" endpoint)
//
// Everything is best-effort: any failure yields fewer names, never an error.
//
// SPDX-License-Identifier: MIT

// 8-char on-chain collection tag -> friendly label for the chip.
export const COLLECTION_NAMES = {
  ATTRIBUT: "Attribute",
  ELEMENTS: "Elements",
  FINALOG1: "Last Relic",
  GENESIS1: "Genesis Relic",
  OGSEALV1: "Vintage Seal",
  OGSEALT1: "Vintage Seal",
};

const NAME_MAX = 32; // on-chain names are <=31 bytes; leave a margin

// Trim, strip C0 controls + DEL + angle brackets, collapse whitespace, cap.
// Forged names are user-chosen, so treat them as untrusted display text.
export function sanitizeName(v) {
  if (typeof v !== "string") return null;
  const s = v
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .replace(/[<>]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, NAME_MAX);
  return s.length ? s : null;
}

// Schema-2 name-on-chain: commitment = [len][utf8 name][zero pad]. Returns the
// decoded name or null if it isn't a valid length-prefixed printable string.
export function nameFromCommitment(commitmentHex) {
  if (typeof commitmentHex !== "string" || !/^[0-9a-fA-F]{2,64}$/.test(commitmentHex)) return null;
  const bytes = commitmentHex.match(/../g).map((h) => parseInt(h, 16));
  const len = bytes[0];
  if (len < 1 || len > 31 || 1 + len > bytes.length) return null;
  const nameBytes = bytes.slice(1, 1 + len);
  let name;
  try {
    name = new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(nameBytes));
  } catch {
    return null; // not valid utf-8 -> this commitment is a hash, not a name
  }
  return sanitizeName(name);
}

// The forged personal name from a schema-0 record: the `engraving`. Handles both
// the parsed `record` object and the `record_canonical` JSON string the artifact
// endpoint returns.
function engravingFromRecord(rec) {
  if (!rec || typeof rec !== "object") return null;
  if (rec.record && typeof rec.record === "object" && typeof rec.record.engraving === "string") {
    return sanitizeName(rec.record.engraving);
  }
  if (typeof rec.engraving === "string") return sanitizeName(rec.engraving);
  if (typeof rec.record_canonical === "string") {
    try {
      const parsed = JSON.parse(rec.record_canonical);
      if (typeof parsed.engraving === "string") return sanitizeName(parsed.engraving);
    } catch { /* not json */ }
  }
  return null;
}

async function getJson(url, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { accept: "application/json" } });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * fetchRelicNames(address, opts) -> [{ name, collection, collectionName, item, schema, soulbound }]
 *
 * opts: { base="https://btxscan.io", timeoutMs=6000, maxRecordFetches=6, fetchJson=getJson }
 * Never throws; returns [] on any failure. Names are deduped (case-insensitive).
 */
export async function fetchRelicNames(address, opts = {}) {
  const base = (opts.base || "https://btxscan.io").replace(/\/+$/, "");
  const timeoutMs = opts.timeoutMs || 6000;
  const maxRecordFetches = opts.maxRecordFetches ?? 6;
  const fetchJson = opts.fetchJson || getJson;

  const holder = await fetchJson(`${base}/api/relics/holder?address=${encodeURIComponent(address)}`, timeoutMs);
  const held = holder && Array.isArray(holder.held) ? holder.held : [];
  if (held.length === 0) return [];

  const out = [];
  const push = (name, h) => {
    if (!name) return;
    out.push({
      name,
      collection: h.collection || null,
      collectionName: COLLECTION_NAMES[h.collection] || h.collection || "Relic",
      item: typeof h.item === "number" ? h.item : null,
      schema: h.schema,
      soulbound: !!h.soulbound,
    });
  };

  // Schema 2: instant, local, no network.
  for (const h of held) {
    if (h.schema === 2 && typeof h.commitment === "string") push(nameFromCommitment(h.commitment), h);
  }

  // Schema 0: fetch the record's engraving, in parallel, bounded.
  const schema0 = held.filter((h) => h.schema === 0 && typeof h.commitment === "string").slice(0, maxRecordFetches);
  const recs = await Promise.all(
    schema0.map((h) => fetchJson(`${base}/api/artifact/${h.commitment}`, timeoutMs).then((rec) => [h, rec])),
  );
  for (const [h, rec] of recs) push(engravingFromRecord(rec), h);

  // Dedup by name (case-insensitive), keep first, cap the list.
  const seen = new Set();
  const deduped = [];
  for (const r of out) {
    const k = r.name.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    deduped.push(r);
    if (deduped.length >= 8) break;
  }
  return deduped;
}
