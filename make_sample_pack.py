#!/usr/bin/env python3
"""make_sample_pack.py — write a sample AIOpt evidence pack to verify against.

Self-contained: it depends only on `cryptography` + the stdlib and imports
NOTHING from the AIOpt platform. That is deliberate — it doubles as an
executable spec of the pack format, and it proves the verifier and a writer can
be written independently and still agree.

Usage:
    python make_sample_pack.py /tmp/demo          # writes single_party/ + two_party/
    python aiopt_verify.py /tmp/demo/two_party    # -> VERIFIED
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCHEMA = "aiopt_evidence_pack_v1"
ZERO_HASH = "0" * 64

# Fixed timestamps so the same inputs always produce the same pack — determinism
# is a verifiability property, not a nicety (and there is no clock call here).
_TS = ["2026-07-23T09:00:00+00:00", "2026-07-23T09:01:00+00:00",
       "2026-07-23T09:02:00+00:00"]
_CREATED = "2026-07-23T09:10:00+00:00"
_VERDICTS = ["COUNTERSIGNED_PASS", "COUNTERSIGNED_REFUSAL", "COUNTERSIGNED_PASS"]


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fingerprint(pub) -> str:
    return _sha256_hex(pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw))


def build_pack(out_dir, *, two_party: bool = False, n: int = 3):
    """Write a valid pack to out_dir. Returns the manifest dict."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    op = Ed25519PrivateKey.generate()
    actor = Ed25519PrivateKey.generate() if two_party else None

    # ---- ledger.jsonl: chain-hashed, Ed25519-signed records --------------
    lines, prev = [], ZERO_HASH
    for i in range(n):
        core = {"seq": i, "timestamp": _TS[i % len(_TS)],
                "kind": "countersign_verdict",
                "payload": {"verdict": _VERDICTS[i % len(_VERDICTS)], "seq_note": i},
                "prev_hash": prev}
        core_bytes = _canon(core)
        rhash = _sha256_hex(core_bytes)
        rec = {**core, "record_hash": rhash,
               "signature": base64.b64encode(op.sign(core_bytes)).decode("ascii")}
        if actor is not None:
            rec["actor_signature"] = base64.b64encode(actor.sign(core_bytes)).decode("ascii")
        lines.append(json.dumps(rec, sort_keys=True))
        prev = rhash
    ledger_bytes = ("\n".join(lines) + "\n").encode("utf-8")
    (out / "ledger.jsonl").write_bytes(ledger_bytes)

    # ---- manifest.json: signed anchor over count/head/whole-ledger digest -
    core = {"schema": SCHEMA, "created": _CREATED, "record_count": n,
            "first_seq": 0, "last_seq": n - 1, "head_hash": prev,
            "ledger_sha256": _sha256_hex(ledger_bytes),
            "pubkey_fingerprint": _fingerprint(op.public_key()),
            "two_party": two_party,
            "actor_pubkey_fingerprint": _fingerprint(actor.public_key()) if actor else None}
    mhash = _sha256_hex(_canon(core))
    manifest = {**core, "manifest_hash": mhash,
                "manifest_signature": base64.b64encode(
                    op.sign(mhash.encode("utf-8"))).decode("ascii")}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))

    # ---- public keys (verify-only) --------------------------------------
    (out / "pubkey.pem").write_bytes(op.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    if actor is not None:
        (out / "pubkey_actor.pem").write_bytes(actor.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
    return manifest


def main():
    base = Path(sys.argv[1] if len(sys.argv) > 1 else "sample_pack_out")
    build_pack(base / "single_party", two_party=False)
    build_pack(base / "two_party", two_party=True)
    print(f"wrote {base}/single_party and {base}/two_party")
    print(f"verify: python aiopt_verify.py {base}/two_party")


if __name__ == "__main__":
    main()
