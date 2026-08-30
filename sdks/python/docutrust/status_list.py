"""
DocuTrust W3C BitstringStatusList2024 (Python Parity)
Provides compliant W3C Bitstring Status List 2024 multi-bit status checking, gzip compression, and multibase encoding.
"""

import gzip
import base64
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union


class BitstringStatusList2024:
    STATUS_PURPOSES = ("revocation", "suspension")
    VALID_STATUS_SIZES = (1, 2, 4, 8)

    STATUS_VALUES = {
        1: {"VALID": 0, "REVOKED": 1},
        2: {"VALID": 0, "REVOKED": 1, "SUSPENDED": 2, "UNDER_REVIEW": 3},
        4: {"VALID": 0, "REVOKED": 1, "SUSPENDED": 2, "UNDER_REVIEW": 3, "EXPIRED": 4},
        8: {"VALID": 0, "REVOKED": 1, "SUSPENDED": 2, "UNDER_REVIEW": 3, "EXPIRED": 4}
    }

    def __init__(
        self,
        length: int = 100000,
        status_size: int = 1,
        status_purpose: str = "revocation",
        buffer: Optional[bytearray] = None
    ):
        if status_size not in self.VALID_STATUS_SIZES:
            raise ValueError(f"Invalid status_size: {status_size}. Must be 1, 2, 4, or 8.")
        if status_purpose not in self.STATUS_PURPOSES:
            raise ValueError(f"Invalid status_purpose: {status_purpose}.")
        if length <= 0:
            raise ValueError(f"Length must be a positive integer, received {length}.")

        self.length = length
        self.status_size = status_size
        self.status_purpose = status_purpose
        self.total_bits = length * status_size
        self.byte_length = (self.total_bits + 7) // 8

        if buffer is not None:
            self.buffer = bytearray(buffer)
        else:
            self.buffer = bytearray(self.byte_length)

    def get_status(self, index: int) -> int:
        if index < 0 or index >= self.length:
            raise IndexError(f"Index {index} out of bounds for status list of length {self.length}.")

        bit_index = index * self.status_size
        byte_index = bit_index // 8
        bit_offset = bit_index % 8

        if self.status_size == 1:
            return (self.buffer[byte_index] >> (7 - bit_offset)) & 0x01
        elif self.status_size == 2:
            return (self.buffer[byte_index] >> (6 - bit_offset)) & 0x03
        elif self.status_size == 4:
            return (self.buffer[byte_index] >> (4 - bit_offset)) & 0x0F
        elif self.status_size == 8:
            return self.buffer[byte_index]
        return 0

    def set_status(self, index: int, status: int) -> None:
        if index < 0 or index >= self.length:
            raise IndexError(f"Index {index} out of bounds for status list of length {self.length}.")

        max_status = (1 << self.status_size) - 1
        if status < 0 or status > max_status:
            raise ValueError(f"Status value {status} exceeds statusSize {self.status_size} limit ({max_status}).")

        bit_index = index * self.status_size
        byte_index = bit_index // 8
        bit_offset = bit_index % 8

        if self.status_size == 1:
            mask = 0x01 << (7 - bit_offset)
            if status:
                self.buffer[byte_index] |= mask
            else:
                self.buffer[byte_index] &= (~mask & 0xFF)
        elif self.status_size == 2:
            shift = 6 - bit_offset
            mask = 0x03 << shift
            self.buffer[byte_index] = (self.buffer[byte_index] & (~mask & 0xFF)) | ((status & 0x03) << shift)
        elif self.status_size == 4:
            shift = 4 - bit_offset
            mask = 0x0F << shift
            self.buffer[byte_index] = (self.buffer[byte_index] & (~mask & 0xFF)) | ((status & 0x0F) << shift)
        elif self.status_size == 8:
            self.buffer[byte_index] = status & 0xFF

    def is_valid(self, index: int) -> bool:
        return self.get_status(index) == 0

    def is_revoked(self, index: int) -> bool:
        return self.get_status(index) == 1

    def is_suspended(self, index: int) -> bool:
        return self.get_status(index) == 2

    def encode(self, compress: bool = True) -> str:
        data = bytes(self.buffer)
        if compress:
            data = gzip.compress(data)
        b64 = base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')
        return 'u' + b64

    @classmethod
    def decode(
        cls,
        encoded_string: str,
        options: Optional[Dict[str, Any]] = None
    ) -> "BitstringStatusList2024":
        if not encoded_string or not encoded_string.startswith('u'):
            raise ValueError("Invalid multibase encoding: expected 'u' prefix for base64url.")

        options = options or {}
        status_size = options.get("status_size", options.get("statusSize", 1))
        status_purpose = options.get("status_purpose", options.get("statusPurpose", "revocation"))

        b64 = encoded_string[1:]
        padding = (4 - len(b64) % 4) % 4
        raw = base64.urlsafe_b64decode(b64 + '=' * padding)

        try:
            decompressed = gzip.decompress(raw)
        except Exception:
            decompressed = raw

        byte_len = len(decompressed)
        total_bits = byte_len * 8
        derived_length = options.get("length", total_bits // status_size)

        return cls(
            length=derived_length,
            status_size=status_size,
            status_purpose=status_purpose,
            buffer=bytearray(decompressed)
        )

    def generate_credential(self, credential_id: str, issuer_did: str) -> Dict[str, Any]:
        return {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/vc/status-list/v1"
            ],
            "id": credential_id,
            "type": ["VerifiableCredential", "StatusList2024Credential"],
            "issuer": issuer_did,
            "validFrom": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "credentialSubject": {
                "id": f"{credential_id}#list",
                "type": "StatusList2024",
                "statusPurpose": self.status_purpose,
                "statusSize": self.status_size,
                "encodedList": self.encode(True)
            }
        }
