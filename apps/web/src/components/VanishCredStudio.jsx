import React, { useState, useEffect } from 'react';
import { Sparkles, Key, Clock, Lock, Unlock, CheckCircle2, XCircle, RefreshCw, Eye, EyeOff, ShieldAlert } from 'lucide-react';

export default function VanishCredStudio() {
  const [issuerKey, setIssuerKey] = useState({
    publicKeyHex: 'd0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1',
    privateKeyHex: '3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d',
    did: 'did:key:z6MkuIssuerEphemeralVanish2026MasterNode'
  });

  const [subjectDid, setSubjectDid] = useState('did:key:z6MkuRecipientAgentHolder');
  const [claimsJson, setClaimsJson] = useState(() => JSON.stringify({
    medicalAuthCode: 'RX-OPIOID-TEMPORARY-AUTH-2026',
    maxDosageMg: 20,
    validFacilityCode: 'FAC-99201'
  }, null, 2));

  const [ttlSeconds, setTtlSeconds] = useState(60);
  const [issuedTokenData, setIssuedTokenData] = useState(null);
  const [ephemeralKeyInput, setEphemeralKeyInput] = useState('');
  const [verifyResult, setVerifyResult] = useState(null);
  const [showKey, setShowKey] = useState(false);
  const [remainingTime, setRemainingTime] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleIssueToken = async () => {
    setLoading(true);
    try {
      const claims = JSON.parse(claimsJson);
      const res = await fetch('/api/v1/vanish/issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          claims,
          issuerKeyPair: issuerKey,
          subjectDid,
          options: { ttlSeconds }
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Token issuance failed');
      setIssuedTokenData(data);
      setEphemeralKeyInput(data.ephemeralKey);
      setVerifyResult(null);
      setRemainingTime(ttlSeconds);
    } catch (e) {
      alert(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!issuedTokenData || remainingTime === null) return;
    if (remainingTime <= 0) return;

    const timer = setInterval(() => {
      setRemainingTime((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [issuedTokenData, remainingTime]);

  const handleVerifyToken = async () => {
    if (!issuedTokenData?.token) return;
    try {
      const res = await fetch('/api/v1/vanish/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: issuedTokenData.token,
          ephemeralKey: ephemeralKeyInput,
          issuerPublicKey: issuerKey.publicKeyHex
        })
      });

      const data = await res.json();
      setVerifyResult(data);
    } catch (e) {
      setVerifyResult({ valid: false, error: e.message });
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20 font-mono">
              v12.0.0 Forward-Secret Tokens
            </span>
            <span className="text-gray-400 text-xs font-mono">DocuTrustVanishToken2026</span>
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <Sparkles className="w-8 h-8 text-amber-400" />
            Ephemeral Vanish Credentials & Time-Decay Studio
          </h1>
          <p className="text-gray-400 text-sm mt-1 max-w-3xl">
            Issue self-expiring forward-secret credentials with autonomous time-lock commitments. Once the TTL window decays, the credential vanishes and cannot be decrypted even if issuer keys leak.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Claims & Ephemeral Issuance */}
        <div className="lg:col-span-6 space-y-6">
          <div className="bg-gray-900/60 border border-gray-800/80 rounded-2xl p-6 backdrop-blur-sm">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
              <Lock className="w-4 h-4 text-amber-400" />
              Sensitive Ephemeral Claims
            </h3>
            <textarea
              rows={5}
              value={claimsJson}
              onChange={(e) => setClaimsJson(e.target.value)}
              className="w-full bg-gray-950 border border-gray-800 rounded-xl p-3 text-xs font-mono text-gray-200 focus:outline-none focus:border-amber-500 mb-4"
            />

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">
                  Subject DID (Recipient Holder)
                </label>
                <input
                  type="text"
                  value={subjectDid}
                  onChange={(e) => setSubjectDid(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl px-3 py-2 text-xs font-mono text-gray-200 focus:outline-none focus:border-amber-500"
                />
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-gray-400 font-medium">Credential Lifetime (TTL)</span>
                  <span className="text-amber-400 font-mono font-semibold">{ttlSeconds} Seconds</span>
                </div>
                <input
                  type="range"
                  min="10"
                  max="300"
                  step="10"
                  value={ttlSeconds}
                  onChange={(e) => setTtlSeconds(Number(e.target.value))}
                  className="w-full h-2 bg-gray-950 rounded-lg appearance-none cursor-pointer accent-amber-500"
                />
              </div>

              <button
                onClick={handleIssueToken}
                disabled={loading}
                className="w-full mt-2 px-5 py-3 bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-white font-semibold text-xs rounded-xl shadow-lg shadow-amber-500/20 transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
              >
                <Sparkles className="w-4 h-4" />
                {loading ? 'Issuing...' : 'Issue Ephemeral Vanish Token'}
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Active Token & Live Decay Verification */}
        <div className="lg:col-span-6 space-y-6">
          {issuedTokenData ? (
            <div className="bg-gray-900/60 border border-gray-800/80 rounded-2xl p-6 backdrop-blur-sm space-y-5">
              {/* Countdown Timer Badge */}
              <div className="flex items-center justify-between p-4 bg-gray-950 rounded-xl border border-gray-800/80">
                <div className="flex items-center gap-3">
                  <div className={`p-2.5 rounded-xl ${remainingTime > 0 ? 'bg-amber-500/10 text-amber-400' : 'bg-red-500/10 text-red-400'}`}>
                    <Clock className="w-5 h-5" />
                  </div>
                  <div>
                    <span className="text-xs text-gray-400 block">Autonomous Epoch Status</span>
                    <span className={`text-base font-bold font-mono ${remainingTime > 0 ? 'text-amber-300' : 'text-red-400'}`}>
                      {remainingTime > 0 ? `${remainingTime}s REMAINING` : 'TOKEN VANISHED & EXPIRED'}
                    </span>
                  </div>
                </div>

                <span className={`px-2.5 py-1 rounded-full text-[11px] font-mono font-semibold border ${
                  remainingTime > 0 ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-red-500/10 text-red-400 border-red-500/30'
                }`}>
                  {remainingTime > 0 ? 'DECRYPTABLE' : 'VANISHED'}
                </span>
              </div>

              {/* Ephemeral Key Input & Toggle */}
              <div>
                <label className="flex items-center justify-between text-xs font-medium text-gray-400 mb-1">
                  <span>Ephemeral Decryption Key (Single-Use)</span>
                  <button
                    onClick={() => setShowKey(!showKey)}
                    className="text-[11px] text-gray-400 hover:text-gray-200 flex items-center gap-1 cursor-pointer"
                  >
                    {showKey ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    {showKey ? 'Hide' : 'Reveal'}
                  </button>
                </label>
                <input
                  type={showKey ? 'text' : 'password'}
                  value={ephemeralKeyInput}
                  onChange={(e) => setEphemeralKeyInput(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl px-3 py-2 text-xs font-mono text-amber-300 focus:outline-none focus:border-amber-500"
                />
              </div>

              {/* Verify & Decrypt Button */}
              <button
                onClick={handleVerifyToken}
                className="w-full px-4 py-2.5 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-white font-medium text-xs rounded-xl flex items-center justify-center gap-2 transition-colors cursor-pointer"
              >
                <Unlock className="w-4 h-4 text-emerald-400" />
                Verify & Decrypt Ephemeral Claims
              </button>

              {/* Decrypted Claims or Error */}
              {verifyResult && (
                <div className={`p-4 rounded-xl border ${
                  verifyResult.valid ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-red-500/10 border-red-500/30'
                }`}>
                  <div className="flex items-center gap-2 mb-2">
                    {verifyResult.valid ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <XCircle className="w-4 h-4 text-red-400" />
                    )}
                    <span className={`text-xs font-semibold ${verifyResult.valid ? 'text-emerald-300' : 'text-red-300'}`}>
                      {verifyResult.valid ? 'Active & Decrypted Successfully' : 'Decryption Failed (Token Expired or Key Corrupted)'}
                    </span>
                  </div>

                  {verifyResult.valid ? (
                    <pre className="bg-gray-950/80 p-3 rounded-lg text-[11px] font-mono text-gray-200 border border-gray-800/80 overflow-x-auto">
                      {JSON.stringify(verifyResult.claims, null, 2)}
                    </pre>
                  ) : (
                    <p className="text-xs text-red-400 font-mono">{verifyResult.error || verifyResult.errors?.join(', ') || 'Decryption failed'}</p>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="h-full min-h-[250px] flex flex-col items-center justify-center border border-dashed border-gray-800 rounded-2xl p-8 text-center bg-gray-900/20">
              <Sparkles className="w-12 h-12 text-gray-600 mb-3 animate-pulse" />
              <h4 className="text-sm font-semibold text-gray-400">No Ephemeral Token Active</h4>
              <p className="text-xs text-gray-500 max-w-sm mt-1">
                Configure your sensitive claims and desired TTL seconds on the left, then click "Issue Ephemeral Vanish Token".
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
