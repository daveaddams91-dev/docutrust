"""
Multi-Chain Ledger Anchor and Calldata Formatter for Python SDK.
"""

import os
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from .crypto import sha256_hex


CHAIN_CONFIGS = {
    "ethereum": {
        "chainId": 1,
        "networkName": "Ethereum Mainnet",
        "defaultContractAddress": "0x8888888888888888888888888888888888888888",
        "explorerTxBaseUrl": "https://etherscan.io/tx/"
    },
    "polygon": {
        "chainId": 137,
        "networkName": "Polygon PoS",
        "defaultContractAddress": "0x8888888888888888888888888888888888888888",
        "explorerTxBaseUrl": "https://polygonscan.com/tx/"
    },
    "arbitrum": {
        "chainId": 42161,
        "networkName": "Arbitrum One",
        "defaultContractAddress": "0x8888888888888888888888888888888888888888",
        "explorerTxBaseUrl": "https://arbiscan.io/tx/"
    },
    "base": {
        "chainId": 8453,
        "networkName": "Base Mainnet",
        "defaultContractAddress": "0x8888888888888888888888888888888888888888",
        "explorerTxBaseUrl": "https://basescan.org/tx/"
    },
    "solana": {
        "networkName": "Solana Mainnet-Beta",
        "defaultContractAddress": "DocuTrust1111111111111111111111111111111111",
        "explorerTxBaseUrl": "https://solscan.io/tx/"
    },
    "bitcoin": {
        "networkName": "Bitcoin Mainnet",
        "explorerTxBaseUrl": "https://mempool.space/tx/"
    }
}


class MultiChainLedgerAnchor:
    @staticmethod
    def format_evm_calldata(merkle_root: str, batch_count: int, memo: str = "DocuTrust Anchor") -> str:
        clean_root = merkle_root.replace("0x", "").rjust(64, "0")
        selector = "892a4b12"
        param1 = clean_root
        param2 = batch_count.to_bytes(32, byteorder="big").hex()
        param3 = (96).to_bytes(32, byteorder="big").hex()

        str_bytes = memo.encode("utf-8")
        str_len_hex = len(str_bytes).to_bytes(32, byteorder="big").hex()
        pad_len = ((len(str_bytes) + 31) // 32) * 32 or 32
        str_padded = str_bytes.ljust(pad_len, b"\x00").hex()

        return "0x" + selector + param1 + param2 + param3 + str_len_hex + str_padded

    @staticmethod
    def format_bitcoin_op_return(merkle_root: str, batch_count: int) -> str:
        clean_root = merkle_root.replace("0x", "").rjust(64, "0")
        root_bytes = bytes.fromhex(clean_root)
        prefix = b"DOCU"
        count_bytes = batch_count.to_bytes(4, byteorder="big")
        payload = prefix + root_bytes + count_bytes
        return "0x6a28" + payload.hex()

    @staticmethod
    def format_solana_instruction(merkle_root: str, batch_count: int) -> str:
        clean_root = merkle_root.replace("0x", "").rjust(64, "0")
        root_bytes = bytes.fromhex(clean_root)
        disc = hashlib.sha256(b"global:anchor_merkle_batch").digest()[:8]
        count_bytes = batch_count.to_bytes(8, byteorder="little")
        payload = disc + root_bytes + count_bytes
        return "0x" + payload.hex()

    @staticmethod
    def format_anchor(
        chain: str,
        merkle_root: str,
        batch_count: int,
        memo: str = "DocuTrust Merkle Batch Anchor"
    ) -> Dict[str, Any]:
        config = CHAIN_CONFIGS.get(chain, CHAIN_CONFIGS["ethereum"])
        clean_root = merkle_root if merkle_root.startswith("0x") else "0x" + merkle_root
        now = datetime.now(timezone.utc).isoformat()
        sim_tx = "0x" + sha256_hex(f"{chain}:{clean_root}:{batch_count}:{now}")

        res = {
            "chain": chain,
            "networkName": config["networkName"],
            "merkleRoot": clean_root,
            "batchCount": batch_count,
            "timestamp": now,
            "memo": memo,
            "targetContract": config.get("defaultContractAddress"),
            "simulatedTxHash": sim_tx,
            "explorerUrl": f"{config['explorerTxBaseUrl']}{sim_tx}"
        }

        if chain == "bitcoin":
            res["opReturnHex"] = MultiChainLedgerAnchor.format_bitcoin_op_return(clean_root, batch_count)
        elif chain == "solana":
            res["instructionDataHex"] = MultiChainLedgerAnchor.format_solana_instruction(clean_root, batch_count)
        else:
            res["calldataHex"] = MultiChainLedgerAnchor.format_evm_calldata(clean_root, batch_count, memo)

        return res
