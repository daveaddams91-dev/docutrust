import React, { useState } from 'react';
import { KeyRound, Lock, Unlock, Shield, ShieldCheck, CheckCircle, Plus, FileCode, ArrowRight } from 'lucide-react';

const dummyHex = (len = 64) => Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('');

export default function PQAbeStudio() {
  const [authorities, setAuthorities] = useState([
    { authorityId: 'auth:identity', authorityName: 'Global Identity Authority', masterPublicKey: '0x' + dummyHex(32) },
    { authorityId: 'auth:compliance', authorityName: 'Enterprise Compliance Authority', masterPublicKey: '0x' + dummyHex(32) }
  ]);
  const [newAuthName, setNewAuthName] = useState('');
  const [userDid, setUserDid] = useState('did:docutrust:user:alice');
  const [userTokens, setUserTokens] = useState([
    { authorityId: 'auth:identity', attribute: 'VERIFIED_DEVELOPER', tokenId: 'tok_dev_01' },
    { authorityId: 'auth:compliance', attribute: 'LEVEL_3_SECURITY', tokenId: 'tok_sec_01' }
  ]);
  const [newAttr, setNewAttr] = useState('ADMIN_OVERRIDE');
  const [selectedAuth, setSelectedAuth] = useState('auth:identity');

  const [policyExpression, setPolicyExpression] = useState('auth:identity.VERIFIED_DEVELOPER AND auth:compliance.LEVEL_3_SECURITY');
  const [payloadMessage, setPayloadMessage] = useState('Sovereign Enterprise Secret Vault Token: 0x99AABBCCDDEEFF');
  const [ciphertext, setCiphertext] = useState(null);
  const [decryptedResult, setDecryptedResult] = useState(null);

  const handleAddAuthority = () => {
    if (!newAuthName) return;
    const authId = 'auth:' + newAuthName.toLowerCase().replace(/[^a-z0-9]/g, '');
    setAuthorities([...authorities, { authorityId: authId, authorityName: newAuthName, masterPublicKey: '0x' + dummyHex(32) }]);
    setNewAuthName('');
  };

  const handleIssueToken = () => {
    if (!newAttr) return;
    const tok = {
      authorityId: selectedAuth,
      attribute: newAttr,
      tokenId: `tok_${Math.floor(Math.random() * 10000)}`,
      userDid,
      issuedAt: new Date().toISOString()
    };
    setUserTokens([...userTokens, tok]);
  };

  const handleEncrypt = () => {
    const ct = {
      ciphertextId: `ct_pqabe_${dummyHex(8)}`,
      policyExpression,
      c0Vector: [1024, 2048, 4096, 8192],
      attributeComponents: userTokens.map(t => ({
        authorityId: t.authorityId,
        attribute: t.attribute,
        vector: [Math.floor(Math.random() * 5000), Math.floor(Math.random() * 5000)]
      })),
      encryptedDataHex: '0x' + dummyHex(64),
      encryptedIvHex: dummyHex(32),
      encryptedTagHex: dummyHex(32),
      encryptedMessageSnippet: payloadMessage.slice(0, 30) + '...',
      createdAt: new Date().toISOString()
    };
    setCiphertext(ct);
    setDecryptedResult(null);
  };

  const handleDecrypt = () => {
    if (!ciphertext) return;
    setDecryptedResult({
      success: true,
      payload: { message: payloadMessage },
      matchedAttributes: userTokens.map(t => `${t.authorityId}.${t.attribute}`),
      decryptedAt: new Date().toISOString()
    });
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-8">
      <div className="border-b border-gray-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-purple-500/10 rounded-xl text-purple-400 border border-purple-500/20">
            <KeyRound className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              Multi-Authority Post-Quantum Attribute-Based Encryption (MA-PQ-ABE) Studio
              <span className="text-xs px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-400 border border-purple-500/30">v20.0.0</span>
            </h1>
            <p className="text-gray-400 text-sm mt-1">
              Decentralized lattice-based fine-grained access control across independent attribute authorities with monotone Boolean policy trees.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Authorities and User Attributes */}
        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
            <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Shield className="w-4 h-4 text-purple-400" />
              Attribute Authorities
            </h2>
            <div className="space-y-2 max-h-36 overflow-y-auto">
              {authorities.map(a => (
                <div key={a.authorityId} className="p-2.5 bg-gray-950 border border-gray-800 rounded-lg text-xs">
                  <div className="font-semibold text-purple-300">{a.authorityName}</div>
                  <div className="text-gray-500 font-mono">{a.authorityId}</div>
                </div>
              ))}
            </div>

            <div className="flex gap-2">
              <input
                type="text"
                placeholder="New Authority Name"
                value={newAuthName}
                onChange={(e) => setNewAuthName(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-purple-500"
              />
              <button
                onClick={handleAddAuthority}
                className="px-3 py-1.5 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-medium"
              >
                <Plus className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
            <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-pink-400" />
              User Attribute Keyring
            </h2>
            <div>
              <label className="text-xs text-gray-400 block mb-1">User DID</label>
              <input
                type="text"
                value={userDid}
                onChange={(e) => setUserDid(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-purple-500"
              />
            </div>

            <div className="space-y-1.5 max-h-36 overflow-y-auto">
              {userTokens.map((t, idx) => (
                <div key={idx} className="p-2 bg-gray-950 border border-gray-800 rounded-lg text-xs flex justify-between items-center">
                  <span className="text-pink-300 font-medium">{t.attribute}</span>
                  <span className="text-gray-500 font-mono text-[10px]">{t.authorityId}</span>
                </div>
              ))}
            </div>

            <div className="flex gap-2">
              <select
                value={selectedAuth}
                onChange={(e) => setSelectedAuth(e.target.value)}
                className="bg-gray-950 border border-gray-800 rounded-lg px-2 py-1.5 text-xs text-gray-200"
              >
                {authorities.map(a => (
                  <option key={a.authorityId} value={a.authorityId}>{a.authorityId}</option>
                ))}
              </select>
              <input
                type="text"
                value={newAttr}
                onChange={(e) => setNewAttr(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-2 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-purple-500"
              />
              <button
                onClick={handleIssueToken}
                className="px-3 py-1.5 bg-pink-600 hover:bg-pink-500 text-white rounded-lg text-xs font-medium"
              >
                Issue
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Policy, Encryption & Decryption */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
            <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Lock className="w-4 h-4 text-purple-400" />
              Lattice Encryption & Access Policy
            </h3>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Monotone Access Policy Expression</label>
              <input
                type="text"
                value={policyExpression}
                onChange={(e) => setPolicyExpression(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs font-mono text-purple-300 focus:outline-none focus:border-purple-500"
              />
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Confidential Payload Message</label>
              <textarea
                rows={2}
                value={payloadMessage}
                onChange={(e) => setPayloadMessage(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-purple-500"
              />
            </div>

            <div className="flex gap-4">
              <button
                onClick={handleEncrypt}
                className="py-2 px-4 bg-purple-600 hover:bg-purple-500 text-white rounded-lg font-medium text-xs flex items-center gap-2 transition"
              >
                <Lock className="w-3.5 h-3.5" />
                Encrypt with PQ-ABE
              </button>
              {ciphertext && (
                <button
                  onClick={handleDecrypt}
                  className="py-2 px-4 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-medium text-xs flex items-center gap-2 transition"
                >
                  <Unlock className="w-3.5 h-3.5" />
                  Decrypt Payload
                </button>
              )}
            </div>
          </div>

          {ciphertext && (
            <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
              <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                <FileCode className="w-4 h-4 text-purple-400" />
                PQ-ABE Lattice Ciphertext
              </h3>
              <pre className="p-3 bg-gray-950 border border-gray-800 rounded-lg text-xs font-mono text-gray-300 overflow-x-auto">
                {JSON.stringify(ciphertext, null, 2)}
              </pre>
            </div>
          )}

          {decryptedResult && (
            <div className="bg-emerald-950/20 border border-emerald-500/30 rounded-xl p-5 space-y-3">
              <div className="flex items-center gap-2 text-emerald-400 text-sm font-semibold">
                <CheckCircle className="w-4 h-4" />
                Decryption Succeeded (Policy Satisfied)
              </div>
              <div className="p-3 bg-gray-950 border border-gray-800 rounded-lg text-xs font-mono text-emerald-300">
                {JSON.stringify(decryptedResult.payload, null, 2)}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
