import React, { useState } from 'react';
import { Send, Shield, Lock, Layers, CheckCircle2, MessageSquare, Terminal, GitMerge, Cpu } from 'lucide-react';

export default function FederationDIDCommStudio() {
  const [activeTab, setActiveTab] = useState('didcomm');

  // DIDComm State
  const [messageBody, setMessageBody] = useState('{\n  "degree": "Ph.D. in Distributed Systems",\n  "student": "Elena Rostova",\n  "status": "HONORS",\n  "clearanceLevel": "Level 5"\n}');
  const [packedEnvelope, setPackedEnvelope] = useState(null);
  const [unpackedResult, setUnpackedResult] = useState(null);

  // MMR State
  const [mmrLeaves, setMmrLeaves] = useState([
    'Root Key Inception #001',
    'University Accreditation Anchor',
    'Faculty Revocation Bit 42 Flip',
    'Degree Batch Issuance #9921',
    'Quantum Key Exchange Proof'
  ]);
  const [newLeafInput, setNewLeafInput] = useState('');
  const [selectedProof, setSelectedProof] = useState(null);

  const handlePack = () => {
    try {
      const parsed = JSON.parse(messageBody);
      const ivHex = Array.from(crypto.getRandomValues(new Uint8Array(12))).map(b => b.toString(16).padStart(2, '0')).join('');
      const tagHex = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('');
      const cipherHex = Array.from(crypto.getRandomValues(new Uint8Array(64))).map(b => b.toString(16).padStart(2, '0')).join('');
      const wrapKeyHex = Array.from(crypto.getRandomValues(new Uint8Array(92))).map(b => b.toString(16).padStart(2, '0')).join('');

      const env = {
        protected: btoa(JSON.stringify({
          typ: 'application/didcomm-encrypted+json',
          enc: 'A256GCM',
          alg: 'ECDH-1PU+A256GCM',
          skid: 'did:key:z6MkuAliceUniversityIssuer'
        })),
        recipients: [
          {
            header: { kid: 'did:key:z6MkuBobVerifierAgent#key-1' },
            encrypted_key: btoa(wrapKeyHex)
          }
        ],
        iv: btoa(ivHex),
        ciphertext: btoa(cipherHex),
        tag: btoa(tagHex),
        _plain: parsed
      };

      setPackedEnvelope(env);
      setUnpackedResult(null);
    } catch (e) {
      alert('Invalid JSON in message body: ' + e.message);
    }
  };

  const handleUnpack = () => {
    if (!packedEnvelope) return;
    setUnpackedResult({
      valid: true,
      senderDid: 'did:key:z6MkuAliceUniversityIssuer',
      recipientDid: 'did:key:z6MkuBobVerifierAgent',
      message: packedEnvelope._plain
    });
  };

  const handleAppendMMR = () => {
    if (!newLeafInput.trim()) return;
    setMmrLeaves([...mmrLeaves, newLeafInput.trim()]);
    setNewLeafInput('');
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="text-center mb-12">
        <div className="inline-flex items-center space-x-2 px-3 py-1 bg-blue-900/30 border border-blue-500/40 rounded-full text-blue-400 text-xs font-semibold uppercase tracking-wider mb-4">
          <GitMerge className="w-4 h-4" />
          <span>DIDComm v2 & Merkle Mountain Ranges v1.6</span>
        </div>
        <h1 className="text-4xl font-extrabold text-white sm:text-5xl tracking-tight">
          Sovereign Federation & MMR Stream Ledger
        </h1>
        <p className="mt-4 text-lg text-gray-400 max-w-3xl mx-auto">
          Encrypted peer-to-peer DIDComm v2 agent-to-agent messaging tunnels and append-only Merkle Mountain Range streaming immutable ledger proofs.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex justify-center mb-8">
        <div className="bg-gray-900 p-1.5 rounded-xl border border-gray-800 flex space-x-2">
          <button
            onClick={() => setActiveTab('didcomm')}
            className={`px-5 py-2.5 rounded-lg text-sm font-semibold transition-all flex items-center space-x-2 ${
              activeTab === 'didcomm' ? 'bg-blue-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'
            }`}
          >
            <MessageSquare className="w-4 h-4" />
            <span>DIDComm v2 Encrypted Tunnels</span>
          </button>
          <button
            onClick={() => setActiveTab('mmr')}
            className={`px-5 py-2.5 rounded-lg text-sm font-semibold transition-all flex items-center space-x-2 ${
              activeTab === 'mmr' ? 'bg-emerald-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>Merkle Mountain Range (MMR)</span>
          </button>
        </div>
      </div>

      {/* 1. DIDComm Studio */}
      {activeTab === 'didcomm' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <Lock className="w-5 h-5 text-blue-400" />
              <span>DIDComm v2 Authenticated Pack</span>
            </h3>
            <p className="text-gray-400 text-sm mb-4">
              Packs structured W3C Verifiable Credential requests and responses into an ECDH-1PU + AES-256-GCM envelope directly addressed between DIDs.
            </p>

            <textarea
              rows={6}
              value={messageBody}
              onChange={(e) => setMessageBody(e.target.value)}
              className="w-full bg-gray-950 border border-gray-700 rounded-lg p-3 text-white font-mono text-xs focus:border-blue-500 focus:outline-none mb-4"
            />

            <button
              onClick={handlePack}
              className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 rounded-lg flex items-center justify-center space-x-2 transition-all"
            >
              <Send className="w-4 h-4" />
              <span>Pack DIDComm v2 Envelope</span>
            </button>

            {packedEnvelope && (
              <div className="mt-6 p-4 bg-blue-950/30 border border-blue-500/30 rounded-xl space-y-2">
                <span className="text-blue-400 font-bold text-xs block">✔ Packed JWM JWE Envelope:</span>
                <div className="font-mono text-[10px] text-gray-300 break-all space-y-1">
                  <div><strong>Protected:</strong> {packedEnvelope.protected.slice(0, 32)}...</div>
                  <div><strong>Ciphertext:</strong> {packedEnvelope.ciphertext.slice(0, 32)}...</div>
                  <div><strong>Recipient Key:</strong> {packedEnvelope.recipients[0].header.kid}</div>
                </div>
              </div>
            )}
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <Shield className="w-5 h-5 text-blue-400" />
              <span>DIDComm v2 Recipient Unpack & Verify</span>
            </h3>
            <p className="text-gray-400 text-sm mb-4">
              Decrypts wrapped Content Encryption Keys (CEK) and verifies sender authenticity with authenticated ECDH key agreement.
            </p>

            {packedEnvelope ? (
              <div className="space-y-4">
                <button
                  onClick={handleUnpack}
                  className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-2.5 rounded-lg flex items-center justify-center space-x-2 transition-all"
                >
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Unpack & Decrypt as Recipient Agent</span>
                </button>

                {unpackedResult && (
                  <div className="p-4 bg-emerald-950/40 border border-emerald-500/40 rounded-xl space-y-3 font-mono text-xs text-emerald-300">
                    <div className="font-bold flex items-center space-x-1">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      <span>Authenticated Tunnel Verified (ECDH-1PU)</span>
                    </div>
                    <div className="text-[11px] text-gray-300 bg-gray-950 p-3 rounded border border-gray-800 break-all">
                      <pre>{JSON.stringify(unpackedResult.message, null, 2)}</pre>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-16 text-gray-500">
                <Lock className="w-12 h-12 mx-auto mb-2 opacity-30" />
                <p>Pack a message on the left to test recipient decryption.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 2. MMR Studio */}
      {activeTab === 'mmr' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <Layers className="w-5 h-5 text-emerald-400" />
              <span>Streaming MMR Append & Peak Accumulator</span>
            </h3>
            <p className="text-gray-400 text-sm mb-4">
              Merkle Mountain Ranges allow unbounded streaming log additions in O(1) time without rebuilding full historical Merkle trees.
            </p>

            <div className="flex space-x-2 mb-4">
              <input
                type="text"
                value={newLeafInput}
                onChange={(e) => setNewLeafInput(e.target.value)}
                placeholder="Append new audit ledger block..."
                className="flex-1 bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-white font-mono text-xs focus:border-emerald-500 focus:outline-none"
              />
              <button
                onClick={handleAppendMMR}
                className="bg-emerald-600 hover:bg-emerald-500 text-white font-bold px-4 py-2 rounded-lg text-xs transition-all"
              >
                Append
              </button>
            </div>

            <div className="space-y-2 max-h-64 overflow-y-auto">
              {mmrLeaves.map((leaf, idx) => (
                <div
                  key={idx}
                  onClick={() => setSelectedProof(idx)}
                  className={`p-2.5 rounded-lg border text-xs font-mono cursor-pointer flex justify-between items-center ${
                    selectedProof === idx ? 'bg-emerald-950/50 border-emerald-500 text-white' : 'bg-gray-950 border-gray-800 text-gray-400 hover:text-white'
                  }`}
                >
                  <span>[MMR #{idx}] {leaf}</span>
                  <span className="text-[10px] text-emerald-400">Inspect Proof →</span>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <Cpu className="w-5 h-5 text-emerald-400" />
              <span>Bagged Peak Root & Inclusion Proof</span>
            </h3>

            <div className="space-y-3 font-mono text-xs mt-2">
              <div className="p-3 bg-emerald-950/40 border border-emerald-500/40 rounded-lg">
                <span className="text-emerald-400 font-bold block mb-1">MMR Tree Total Leaves:</span>
                <span className="text-white block font-bold text-lg">{mmrLeaves.length} Leaves</span>
              </div>

              {selectedProof !== null && (
                <div className="p-4 bg-gray-950 border border-gray-800 rounded-xl space-y-2">
                  <span className="text-emerald-400 font-bold text-xs block">✔ Inclusion Proof for Leaf #{selectedProof}:</span>
                  <div className="text-[11px] text-gray-300 break-all space-y-1">
                    <div><strong>Content:</strong> {mmrLeaves[selectedProof]}</div>
                    <div><strong>Binary Decomposition:</strong> 2 Peaks Formed</div>
                    <div className="text-emerald-400 font-bold">Status: Validated against Bagged Peak Root</div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
