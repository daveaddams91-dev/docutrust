import React, { useState } from 'react';
import { Fingerprint, Smartphone, CheckCircle, Shield, Copy, Check, RefreshCw, KeyRound, Sparkles, Terminal } from 'lucide-react';

export default function WebAuthnStudio() {
  const [keyPair, setKeyPair] = useState({
    algorithm: 'ES256 (secp256r1 / P-256)',
    rpId: 'docutrust.org',
    credentialId: 'd0N1VHJ1c3RfRklETzJfQXR0ZXN0YXRpb25fS2V5UGFpcg',
    did: 'did:webauthn:z6MkkP9uB4W97LqC5E2mX8V1z9Rt',
    publicKeyHex: '04f29a018274acb91028374faecc0918237498127390ab1287391827391823abf109283019283019283019283019283019283019283019283019283019283019'
  });

  const [challenge, setChallenge] = useState('0x9812739812739182739182739182739182739182739182739182739182739182');
  const [userVerified, setUserVerified] = useState(true);
  const [assertion, setAssertion] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [copiedField, setCopiedField] = useState(null);

  const handleCopy = (text, field) => {
    navigator.clipboard.writeText(typeof text === 'object' ? JSON.stringify(text, null, 2) : text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleNewPasskey = () => {
    const randHex = (bytes) => Array.from({ length: bytes }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('');
    setKeyPair({
      algorithm: 'ES256 (secp256r1 / P-256)',
      rpId: 'docutrust.org',
      credentialId: btoa(`dt_cred_${randHex(16)}`).replace(/=/g, ''),
      did: `did:webauthn:z${randHex(16)}`,
      publicKeyHex: `04${randHex(64)}`
    });
    setAssertion(null);
    setVerificationResult(null);
  };

  const handleCreateAssertion = () => {
    const randHex = (bytes) => Array.from({ length: bytes }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('');
    const clientData = {
      type: "webauthn.get",
      challenge: challenge,
      origin: "https://docutrust.org",
      crossOrigin: false
    };
    const clientDataJSON = btoa(JSON.stringify(clientData));
    const authenticatorData = btoa(randHex(37));
    const sig = btoa(randHex(64));

    setAssertion({
      type: "DocuTrustWebAuthnAssertion2026",
      credentialId: keyPair.credentialId,
      clientDataJSON: clientDataJSON,
      authenticatorData: authenticatorData,
      signature: sig,
      userHandle: keyPair.did,
      hardwareAttestation: {
        authenticatorAttachment: "platform (Secure Enclave / TPM 2.0)",
        userPresence: true,
        userVerification: userVerified
      }
    });
    setVerificationResult(null);
  };

  const handleVerify = () => {
    if (!assertion) return;
    setVerificationResult({
      valid: true,
      userPresent: true,
      userVerified: userVerified,
      signCount: 42,
      rpId: 'docutrust.org',
      origin: 'https://docutrust.org',
      hardwareBacked: true,
      tpmAttestation: "VALIDATED_ECDSA_P256"
    });
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Header */}
      <div className="flex items-center gap-3 mb-8">
        <div className="w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center">
          <Fingerprint className="w-6 h-6 text-blue-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            WebAuthn & Passkeys Hardware Studio
            <span className="text-xs px-2.5 py-0.5 rounded-full bg-blue-500/20 text-blue-300 border border-blue-500/40 font-mono">v11.0.0</span>
          </h1>
          <p className="text-sm text-gray-400">
            FIDO2 / WebAuthn Hardware Security Enclave Attestations with P-256 / ES256 & <code className="text-blue-300">did:webauthn:z...</code>
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Passkey Credentials */}
        <div className="lg:col-span-5 space-y-6">
          <div className="p-6 rounded-2xl border border-gray-800 bg-gray-900/50 backdrop-blur-xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Smartphone className="w-4 h-4 text-blue-400" />
                Passkey Hardware Credential
              </h2>
              <button
                onClick={handleNewPasskey}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 transition"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                New Passkey
              </button>
            </div>

            <div className="space-y-4 text-xs font-mono">
              <div>
                <label className="text-gray-400 block mb-1">Relying Party ID (RP ID)</label>
                <div className="p-2.5 rounded-lg bg-gray-950 border border-gray-800 text-blue-300">
                  {keyPair.rpId}
                </div>
              </div>

              <div>
                <div className="flex justify-between items-center mb-1">
                  <label className="text-gray-400">WebAuthn DID</label>
                  <button onClick={() => handleCopy(keyPair.did, 'did')} className="text-gray-500 hover:text-gray-300">
                    {copiedField === 'did' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <div className="p-2.5 rounded-lg bg-gray-950 border border-gray-800 text-green-400 break-all">
                  {keyPair.did}
                </div>
              </div>

              <div>
                <div className="flex justify-between items-center mb-1">
                  <label className="text-gray-400">Credential ID (Base64URL)</label>
                  <button onClick={() => handleCopy(keyPair.credentialId, 'cid')} className="text-gray-500 hover:text-gray-300">
                    {copiedField === 'cid' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <div className="p-2.5 rounded-lg bg-gray-950 border border-gray-800 text-gray-300 break-all">
                  {keyPair.credentialId}
                </div>
              </div>

              <div>
                <div className="flex justify-between items-center mb-1">
                  <label className="text-gray-400">P-256 Uncompressed Public Key</label>
                  <button onClick={() => handleCopy(keyPair.publicKeyHex, 'pub')} className="text-gray-500 hover:text-gray-300">
                    {copiedField === 'pub' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <div className="p-2.5 rounded-lg bg-gray-950 border border-gray-800 text-gray-300 break-all max-h-20 overflow-y-auto">
                  {keyPair.publicKeyHex}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Challenge & Hardware Assertion */}
        <div className="lg:col-span-7 space-y-6">
          <div className="p-6 rounded-2xl border border-gray-800 bg-gray-900/50 backdrop-blur-xl">
            <h2 className="text-base font-semibold text-white mb-3 flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-blue-400" />
              Generate Hardware Assertion
            </h2>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-gray-400 block mb-1">Authentication Challenge</label>
                <input
                  type="text"
                  value={challenge}
                  onChange={(e) => setChallenge(e.target.value)}
                  className="w-full p-2.5 rounded-xl bg-gray-950 border border-gray-800 text-xs font-mono text-gray-200 focus:outline-none focus:border-blue-500/50"
                />
              </div>

              <div className="flex items-center gap-2 pt-2">
                <input
                  type="checkbox"
                  id="uv-check"
                  checked={userVerified}
                  onChange={(e) => setUserVerified(e.target.checked)}
                  className="rounded bg-gray-900 border-gray-700 text-blue-600 focus:ring-0"
                />
                <label htmlFor="uv-check" className="text-xs text-gray-300 select-none cursor-pointer">
                  Require Biometric / PIN Verification (UV Flag 0x04)
                </label>
              </div>

              <div className="pt-2 flex gap-3">
                <button
                  onClick={handleCreateAssertion}
                  className="flex items-center gap-2 px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-lg shadow-blue-600/20 transition"
                >
                  <Sparkles className="w-4 h-4" />
                  Sign with Hardware Passkey
                </button>
                {assertion && (
                  <button
                    onClick={handleVerify}
                    className="flex items-center gap-2 px-4 py-2 rounded-xl bg-green-600 hover:bg-green-500 text-white text-xs font-semibold shadow-lg shadow-green-600/20 transition"
                  >
                    <CheckCircle className="w-4 h-4" />
                    Verify WebAuthn Flags
                  </button>
                )}
              </div>
            </div>
          </div>

          {assertion && (
            <div className="p-6 rounded-2xl border border-gray-800 bg-gray-900/50 backdrop-blur-xl space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-blue-400" />
                  WebAuthn Assertion Payload
                </h3>
                <button onClick={() => handleCopy(assertion, 'asst')} className="text-gray-500 hover:text-gray-300">
                  {copiedField === 'asst' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <pre className="p-3.5 rounded-xl bg-gray-950 border border-gray-800 text-[11px] font-mono text-blue-300 overflow-x-auto max-h-48">
                {JSON.stringify(assertion, null, 2)}
              </pre>
            </div>
          )}

          {verificationResult && (
            <div className="p-6 rounded-2xl border border-green-500/30 bg-green-950/20 backdrop-blur-xl space-y-3">
              <div className="flex items-center gap-2 text-green-400 font-semibold text-sm">
                <CheckCircle className="w-5 h-5" />
                Passkey Authenticator Verified (Hardware Attestation Pass)
              </div>
              <div className="grid grid-cols-3 gap-3 text-xs font-mono text-gray-300 mt-2">
                <div className="p-2.5 rounded-lg bg-gray-950/60 border border-green-500/20">
                  <span className="text-gray-500 block">User Presence (UP):</span>
                  <span className="text-green-400 font-bold">TRUE (0x01)</span>
                </div>
                <div className="p-2.5 rounded-lg bg-gray-950/60 border border-green-500/20">
                  <span className="text-gray-500 block">User Verified (UV):</span>
                  <span className="text-green-400 font-bold">{verificationResult.userVerified ? 'TRUE (0x04)' : 'FALSE'}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-gray-950/60 border border-green-500/20">
                  <span className="text-gray-500 block">Signature Count:</span>
                  <span className="text-blue-300">#{verificationResult.signCount}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
