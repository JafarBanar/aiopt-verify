"""Independent test for aiopt-verify — no dependency on the AIOpt platform.

It builds packs with make_sample_pack (cryptography-only) and asserts the
verifier passes a clean pack and FAILS every tamper: modification, middle
deletion, last-record truncation, wrong key, and — for two-party packs — a
stripped or wrong actor signature.

Run:  pip install cryptography pytest && pytest test_aiopt_verify.py
"""
import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aiopt_verify as v
from make_sample_pack import build_pack


def _failed(checks):
    return [name for name, ok, _ in checks if not ok]


def test_clean_single_party_verifies(tmp_path):
    build_pack(tmp_path, two_party=False)
    ok, checks = v.verify_pack(str(tmp_path))
    assert ok, _failed(checks)


def test_clean_two_party_verifies(tmp_path):
    build_pack(tmp_path, two_party=True)
    ok, checks = v.verify_pack(str(tmp_path))
    assert ok, _failed(checks)
    assert "actor_signatures" in [n for n, _, _ in checks]


def test_modified_record_fails(tmp_path):
    build_pack(tmp_path, two_party=False)
    lines = (tmp_path / "ledger.jsonl").read_text().splitlines()
    rec = json.loads(lines[1]); rec["payload"]["seq_note"] = 999
    lines[1] = json.dumps(rec, sort_keys=True)
    (tmp_path / "ledger.jsonl").write_text("\n".join(lines) + "\n")
    ok, checks = v.verify_pack(str(tmp_path))
    assert not ok
    assert "record_signatures" in _failed(checks) and "ledger_digest" in _failed(checks)


def test_deleted_middle_record_fails(tmp_path):
    build_pack(tmp_path, two_party=False)
    lines = (tmp_path / "ledger.jsonl").read_text().splitlines()
    del lines[1]
    (tmp_path / "ledger.jsonl").write_text("\n".join(lines) + "\n")
    ok, checks = v.verify_pack(str(tmp_path))
    assert not ok
    assert "chain_linkage" in _failed(checks) and "manifest_count" in _failed(checks)


def test_truncated_last_record_fails(tmp_path):
    """The headline property: dropping the newest record is detected."""
    build_pack(tmp_path, two_party=False)
    lines = (tmp_path / "ledger.jsonl").read_text().splitlines()[:-1]
    (tmp_path / "ledger.jsonl").write_text("\n".join(lines) + "\n")
    ok, checks = v.verify_pack(str(tmp_path))
    assert not ok
    for name in ("manifest_count", "manifest_head", "ledger_digest"):
        assert name in _failed(checks)


def test_wrong_pubkey_fails(tmp_path):
    build_pack(tmp_path, two_party=False)
    other = Ed25519PrivateKey.generate()
    (tmp_path / "pubkey.pem").write_bytes(other.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    ok, checks = v.verify_pack(str(tmp_path))
    assert not ok
    assert "pubkey_fingerprint" in _failed(checks)


def test_two_party_stripped_actor_signature_fails(tmp_path):
    build_pack(tmp_path, two_party=True)
    lines = (tmp_path / "ledger.jsonl").read_text().splitlines()
    rec = json.loads(lines[1]); rec.pop("actor_signature")
    lines[1] = json.dumps(rec, sort_keys=True)
    (tmp_path / "ledger.jsonl").write_text("\n".join(lines) + "\n")
    ok, checks = v.verify_pack(str(tmp_path))
    assert not ok
    assert "actor_signatures" in _failed(checks)


def test_forged_manifest_without_key_fails(tmp_path):
    build_pack(tmp_path, two_party=False)
    (tmp_path / "ledger.jsonl").write_text("")
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    manifest["record_count"] = 0
    manifest["manifest_signature"] = base64.b64encode(b"\x00" * 64).decode()
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    ok, checks = v.verify_pack(str(tmp_path))
    assert not ok
    assert "manifest_signature" in _failed(checks)
