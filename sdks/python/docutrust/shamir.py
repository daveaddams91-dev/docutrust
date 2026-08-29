from __future__ import annotations
import os
import hashlib
from typing import List, Dict, Any, Union

# GF(256) tables with irreducible polynomial 0x11d
EXP = [0] * 512
LOG = [0] * 256

def _init_gf256():
    x = 1
    for i in range(255):
        EXP[i] = x
        EXP[i + 255] = x
        LOG[x] = i
        high_bit = x & 0x80
        x = ((x << 1) & 0xff) ^ (0x1d if high_bit else 0)

_init_gf256()

def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return EXP[LOG[a] + LOG[b]]

def _gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("Division by zero in GF(256)")
    if a == 0:
        return 0
    return EXP[(LOG[a] + 255 - LOG[b]) % 255]

def split_secret(secret: Union[str, bytes], total_shares: int, threshold: int) -> List[Dict[str, Any]]:
    """Splits secret into total_shares with reconstruction threshold."""
    if threshold < 2 or threshold > total_shares or total_shares > 255:
        raise ValueError(f"Invalid threshold {threshold} or total_shares {total_shares}")

    secret_bytes = secret.encode('utf-8') if isinstance(secret, str) else secret
    checksum = hashlib.sha256(secret_bytes).hexdigest()[:16]
    shares = [bytearray(len(secret_bytes)) for _ in range(total_shares)]

    for byte_idx, s in enumerate(secret_bytes):
        coeffs = [s] + list(os.urandom(threshold - 1))
        for x in range(1, total_shares + 1):
            y = 0
            for c in reversed(coeffs):
                y = _gf_mul(y, x) ^ c
            shares[x - 1][byte_idx] = y

    return [
        {
            "index": idx + 1,
            "shareHex": bytes(shares[idx]).hex(),
            "threshold": threshold,
            "totalShares": total_shares,
            "checksum": checksum
        }
        for idx in range(total_shares)
    ]

def combine_shares(shares: List[Dict[str, Any]]) -> bytes:
    """Reconstructs secret from any K shares using Lagrange interpolation in GF(256)."""
    if len(shares) < 2:
        raise ValueError("At least 2 shares are required.")

    threshold = shares[0]["threshold"]
    if len(shares) < threshold:
        raise ValueError(f"Insufficient shares: got {len(shares)}, need {threshold}.")

    selected = shares[:threshold]
    share_bufs = [bytes.fromhex(s["shareHex"]) for s in selected]
    secret_len = len(share_bufs[0])
    secret = bytearray(secret_len)
    x_vals = [s["index"] for s in selected]

    for byte_idx in range(secret_len):
        secret_byte = 0
        for i in range(threshold):
            num = 1
            den = 1
            for j in range(threshold):
                if i == j:
                    continue
                num = _gf_mul(num, x_vals[j])
                den = _gf_mul(den, x_vals[i] ^ x_vals[j])
            basis = _gf_div(num, den)
            term = _gf_mul(share_bufs[i][byte_idx], basis)
            secret_byte ^= term
        secret[byte_idx] = secret_byte

    res_bytes = bytes(secret)
    checksum = hashlib.sha256(res_bytes).hexdigest()[:16]
    if shares[0].get("checksum") and checksum != shares[0]["checksum"]:
        raise ValueError("Checksum mismatch in reconstructed Shamir secret.")

    return res_bytes
