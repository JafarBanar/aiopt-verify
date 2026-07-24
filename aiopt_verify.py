#!/usr/bin/env python3
"""aiopt-verify — offline verifier for AIOpt evidence packs.

Verifies a pack (ledger.jsonl + manifest.json + pubkey.pem) with no trust in
AIOpt and no shared code with the writer: it re-derives every hash and checks
every Ed25519 signature itself. Any modification, deletion, or truncation of the
ledger fails, and the manifest cannot have been re-signed without the operator's
private key.

Dependencies: `cryptography` (Ed25519) + Python stdlib. Nothing else.

Usage:
    python aiopt_verify.py /path/to/pack        # human report, exit 0/1
    python aiopt_verify.py /path/to/pack --json # machine-readable

Exit code 0 = every check passed; 1 = verification failed; 2 = usage/IO error.
"""
import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.stderr.write("aiopt-verify needs the 'cryptography' package: pip install cryptography\n")
    sys.exit(2)

SCHEMA = "aiopt_evidence_pack_v1"
ZERO_HASH = "0" * 64


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def verify_pack(pack_dir):
    """Return (ok: bool, checks: list[(name, passed, detail)])."""
    pack = Path(pack_dir)
    checks = []

    def check(name, passed, detail=""):
        checks.append((name, bool(passed), detail))
        return passed

    ledger_path = pack / "ledger.jsonl"
    manifest_path = pack / "manifest.json"
    pubkey_path = pack / "pubkey.pem"
    for f in (ledger_path, manifest_path, pubkey_path):
        if not check(f"present:{f.name}", f.exists(), str(f)):
            return False, checks

    raw = ledger_path.read_bytes()
    manifest = json.loads(manifest_path.read_text())
    pub = serialization.load_pem_public_key(pubkey_path.read_bytes())

    check("schema", manifest.get("schema") == SCHEMA, manifest.get("schema", ""))

    # public-key fingerprint must match what the manifest was built against
    fp = sha256_hex(pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw))
    check("pubkey_fingerprint", fp == manifest.get("pubkey_fingerprint"),
          f"pack={fp[:16]}… manifest={str(manifest.get('pubkey_fingerprint'))[:16]}…")

    # two-party packs carry a second (change-author) key; every record must then
    # ALSO carry a valid actor signature, so neither party alone can forge one
    two_party = bool(manifest.get("two_party"))
    actor_pub = None
    if two_party:
        actor_path = pack / "pubkey_actor.pem"
        if check("present:pubkey_actor.pem", actor_path.exists(), str(actor_path)):
            actor_pub = serialization.load_pem_public_key(actor_path.read_bytes())
            afp = sha256_hex(actor_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw))
            check("actor_pubkey_fingerprint",
                  afp == manifest.get("actor_pubkey_fingerprint"),
                  f"pack={afp[:16]}… manifest={str(manifest.get('actor_pubkey_fingerprint'))[:16]}…")

    # per-record: chain linkage, seq monotonicity, record hash, signature(s)
    records = [json.loads(x) for x in raw.decode("utf-8").splitlines() if x.strip()]
    prev = ZERO_HASH
    chain_ok = seq_ok = rhash_ok = sig_ok = True
    actor_sig_ok = True
    for i, rec in enumerate(records):
        core = {k: rec[k] for k in ("seq", "timestamp", "kind", "payload", "prev_hash")}
        if rec["prev_hash"] != prev:
            chain_ok = False
        if rec["seq"] != i:
            seq_ok = False
        core_bytes = canon(core)
        rh = sha256_hex(core_bytes)
        if rh != rec["record_hash"]:
            rhash_ok = False
        try:
            pub.verify(base64.b64decode(rec["signature"]), core_bytes)
        except (InvalidSignature, Exception):
            sig_ok = False
        if actor_pub is not None:
            try:
                actor_pub.verify(base64.b64decode(rec["actor_signature"]), core_bytes)
            except (InvalidSignature, KeyError, Exception):
                actor_sig_ok = False
        prev = rec["record_hash"]
    check("record_count>0", len(records) > 0, str(len(records)))
    check("chain_linkage", chain_ok)
    check("seq_monotonic", seq_ok)
    check("record_hashes", rhash_ok)
    check("record_signatures", sig_ok)
    if two_party:
        check("actor_signatures", actor_sig_ok)

    # manifest anchors: count, head, whole-ledger digest — this is what catches
    # truncation (deleting the last record) that a plain chain would miss
    check("manifest_count", manifest.get("record_count") == len(records),
          f"manifest={manifest.get('record_count')} actual={len(records)}")
    head = records[-1]["record_hash"] if records else ZERO_HASH
    check("manifest_head", manifest.get("head_hash") == head)
    check("manifest_last_seq", manifest.get("last_seq") == (len(records) - 1))
    check("ledger_digest", manifest.get("ledger_sha256") == sha256_hex(raw))

    # manifest self-hash and signature. The two-party fields are part of the
    # signed core only when present, so this verifies both v1 single-party packs
    # (no such fields) and two-party packs without a schema bump.
    core_keys = ["schema", "created", "record_count", "first_seq", "last_seq",
                 "head_hash", "ledger_sha256", "pubkey_fingerprint"]
    if "two_party" in manifest:
        core_keys += ["two_party", "actor_pubkey_fingerprint"]
    core = {k: manifest[k] for k in core_keys}
    mhash = sha256_hex(canon(core))
    check("manifest_hash", mhash == manifest.get("manifest_hash"))
    try:
        pub.verify(base64.b64decode(manifest["manifest_signature"]),
                   manifest["manifest_hash"].encode("utf-8"))
        check("manifest_signature", True)
    except (InvalidSignature, Exception):
        check("manifest_signature", False)

    ok = all(passed for _, passed, _ in checks)
    return ok, checks


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pack", help="path to the evidence-pack directory")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    if not Path(args.pack).is_dir():
        sys.stderr.write(f"not a directory: {args.pack}\n")
        return 2

    ok, checks = verify_pack(args.pack)
    if args.json:
        print(json.dumps({
            "ok": ok,
            "checks": [{"name": n, "passed": p, "detail": d} for n, p, d in checks],
        }, indent=2))
    else:
        for name, passed, detail in checks:
            mark = "PASS" if passed else "FAIL"
            print(f"  [{mark}] {name}" + (f"  ({detail})" if detail and not passed else ""))
        print()
        print("RESULT: VERIFIED — pack is authentic and complete" if ok
              else "RESULT: FAILED — pack has been altered, truncated, or is not authentic")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
