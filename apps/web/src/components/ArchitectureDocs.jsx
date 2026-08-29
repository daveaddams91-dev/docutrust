import React from 'react';
import { BookOpen, ShieldCheck, Lock, Layers, EyeOff, CheckCircle2, GitBranch } from 'lucide-react';

export default function ArchitectureDocs() {
  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-12 text-left space-y-12">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 text-xs font-mono text-blue-400 mb-2 uppercase tracking-widest">
          <BookOpen className="w-3.5 h-3.5" />
          <span>Core Cryptographic Specification</span>
        </div>
        <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          System Architecture & Standards
        </h2>
        <p className="text-sm text-gray-400 mt-2">
          An open, mathematically verifiable architecture built on global interoperability standards.
        </p>
      </div>

      {/* 1. W3C VC 2.0 & Decentralized Identifiers */}
      <div className="glass-card p-6 sm:p-8 rounded-2xl border border-gray-800 space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-blue-500/10 text-blue-400 flex items-center justify-center">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <h3 className="text-lg font-bold text-white">1. W3C Verifiable Credentials 2.0 & DIDs</h3>
        </div>
        <p className="text-sm text-gray-300 leading-relaxed">
          DocuTrust strictly follows the W3C Verifiable Credentials Data Model v2.0 standard. 
          Every issuer and recipient is identified via standard Decentralized Identifiers (<code className="text-blue-400 bg-gray-900 px-1.5 py-0.5 rounded font-mono text-xs">did:key</code>, <code className="text-blue-400 bg-gray-900 px-1.5 py-0.5 rounded font-mono text-xs">did:web</code>), 
          ensuring sovereign control without centralized root certificate authorities.
        </p>
      </div>

      {/* 2. JCS Canonicalization RFC 8785 */}
      <div className="glass-card p-6 sm:p-8 rounded-2xl border border-gray-800 space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center">
            <Lock className="w-4 h-4" />
          </div>
          <h3 className="text-lg font-bold text-white">2. Deterministic Canonicalization (RFC 8785 JCS)</h3>
        </div>
        <p className="text-sm text-gray-300 leading-relaxed">
          Before digital signing, the JSON document is normalized using JSON Canonicalization Scheme (RFC 8785). 
          This guarantees that JSON key ordering, Unicode encodings, and whitespace differences never cause false signature verification failures.
        </p>
      </div>

      {/* 3. Merkle Tree Batch Anchoring & Domain Separation */}
      <div className="glass-card p-6 sm:p-8 rounded-2xl border border-gray-800 space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-purple-500/10 text-purple-400 flex items-center justify-center">
            <Layers className="w-4 h-4" />
          </div>
          <h3 className="text-lg font-bold text-white">3. Merkle Tree Batch Anchoring with Domain Separation</h3>
        </div>
        <p className="text-sm text-gray-300 leading-relaxed">
          To prevent second-preimage collision attacks (RFC 6962), leaf nodes are hashed with a <code className="text-purple-400 bg-gray-900 px-1.5 py-0.5 rounded font-mono text-xs">0x00</code> prefix byte 
          and interior nodes are hashed with a <code className="text-purple-400 bg-gray-900 px-1.5 py-0.5 rounded font-mono text-xs">0x01</code> prefix byte. 
          This allows 10,000+ certificates to be compressed into a single 32-byte hash committed to public blockchains (Polygon, Ethereum Layer 2s).
        </p>
      </div>

      {/* 4. Zero-Knowledge Selective Disclosure */}
      <div className="glass-card p-6 sm:p-8 rounded-2xl border border-gray-800 space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 text-cyan-400 flex items-center justify-center">
            <EyeOff className="w-4 h-4" />
          </div>
          <h3 className="text-lg font-bold text-white">4. Zero-Knowledge Salted Claim Privacy</h3>
        </div>
        <p className="text-sm text-gray-300 leading-relaxed">
          Each individual claim in the credential is assigned an independent 128-bit cryptographic salt:
          <br/>
          <code className="block p-3 mt-2 bg-black rounded-lg text-emerald-400 font-mono text-xs">
            BlindedClaimHash = SHA-256( Salt_i || "::" || ClaimKey_i || "::" || JCS(ClaimValue_i) )
          </code>
          When a recipient reveals only their Degree title, they disclose only the specific salt for that claim. 
          The verifier reconstructs the Merkle branch and confirms the issuer signature against the claims root without uncovering blinded attributes.
        </p>
      </div>

      {/* 5. EIP-712 Ethereum Structured Typing */}
      <div className="glass-card p-6 sm:p-8 rounded-2xl border border-gray-800 space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-amber-500/10 text-amber-400 flex items-center justify-center">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <h3 className="text-lg font-bold text-white">5. Ethereum EIP-712 Structured Credential Suite</h3>
        </div>
        <p className="text-sm text-gray-300 leading-relaxed">
          Integrates <code className="text-amber-400 bg-gray-900 px-1.5 py-0.5 rounded font-mono text-xs">EthereumEip712Signature2026</code> with deterministic <code className="text-amber-400 bg-gray-900 px-1.5 py-0.5 rounded font-mono text-xs">did:pkh:eip155</code> identifiers, domain separators, and Keccak-256 type hashing for native EVM and smart-contract verification.
        </p>
      </div>

      {/* 6. Social Recovery & Timelocked Escrow */}
      <div className="glass-card p-6 sm:p-8 rounded-2xl border border-gray-800 space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center">
            <GitBranch className="w-4 h-4" />
          </div>
          <h3 className="text-lg font-bold text-white">6. Decentralized Guardian Social Recovery & Timelocks</h3>
        </div>
        <p className="text-sm text-gray-300 leading-relaxed">
          Protects high-value institutional root keys through K-of-N Shamir Secret Sharing mapped to authenticated Guardian DIDs with configurable timelock challenge periods and real-time Owner Veto guards.
        </p>
      </div>

      {/* 7. Multi-Chain Ledger Anchoring */}
      <div className="glass-card p-6 sm:p-8 rounded-2xl border border-gray-800 space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-violet-500/10 text-violet-400 flex items-center justify-center">
            <Layers className="w-4 h-4" />
          </div>
          <h3 className="text-lg font-bold text-white">7. Cross-Chain Sovereign Ledger Anchoring</h3>
        </div>
        <p className="text-sm text-gray-300 leading-relaxed">
          Standardized byte-level calldata formatting for EVM (Ethereum, Arbitrum, Base, Polygon), Solana Anchor program instructions, and Bitcoin OP_RETURN scripts ensuring tamper-proof Merkle root provenance across any public ledger.
        </p>
      </div>
    </div>
  );
}
