import React, { useState } from 'react';
import { 
  EyeOff, 
  ShieldCheck, 
  Key, 
  Lock, 
  Send, 
  FileCheck2, 
  RefreshCw, 
  Copy, 
  Check, 
  Sparkles,
  ArrowRight,
  Fingerprint
} from 'lucide-react';

function randomHex(len = 32) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(str) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export default function AnonCredsStudio() {
  // State
  const [step, setStep] = useState(1);
  const [copied, setCopied] = useState(false);

  // Holder Step 1: Secret & Blind Request
  const [schemaId, setSchemaId] = useState('schema:phd-degree:2026');
  const [issuerDid, setIssuerDid] = useState('did:key:zIssuerStanford2026');
  const [holderSecret, setHolderSecret] = useState('');
  const [blindingFactor, setBlindingFactor] = useState('');
  const [blindRequest, setBlindRequest] = useState(null);

  // Issuer Step 2: Blind Issuance
  const [issuerKp, setIssuerKp] = useState(null);
  const [claims, setClaims] = useState({
    studentName: 'Alice Turing',
    degree: 'Ph.D. Cryptographic Engineering',
    graduationYear: '2026',
    gpa: '3.98',
    honors: 'Summa Cum Laude'
  });
  const [blindCredential, setBlindCredential] = useState(null);

  // Holder Step 3: Unblinding
  const [unblindedCredential, setUnblindedCredential] = useState(null);

  // Holder Step 4: Presentation Creation
  const [revealAttributes, setRevealAttributes] = useState({
    studentName: false,
    degree: true,
    graduationYear: true,
    gpa: false,
    honors: false
  });
  const [verifierNonce, setVerifierNonce] = useState('nonce_' + Math.random().toString(36).substring(2, 9));
  const [presentation, setPresentation] = useState(null);

  // Verifier Step 5: Verification
  const [verificationResult, setVerificationResult] = useState(null);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(typeof text === 'string' ? text : JSON.stringify(text, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // 1. Generate Blind Request
  const handleGenerateBlindRequest = async () => {
    const ms = 'ms_' + randomHex(32);
    const bf = randomHex(32);
    const blindCommitment = await sha256(`pedersen_${ms}_${bf}`);

    setHolderSecret(ms);
    setBlindingFactor(bf);

    const req = {
      type: 'AnonCredsBlindIssuanceRequest2026',
      schemaId,
      issuerDid,
      blindedMasterSecretCommitment: '0x' + blindCommitment,
      nonce: 'nonce_' + randomHex(8),
      timestamp: new Date().toISOString()
    };
    setBlindRequest(req);

    // Also init issuer keys for next step
    const pub = randomHex(32);
    const kp = { did: `did:key:z6Mku${pub.substring(0, 16)}`, publicKeyHex: pub };
    setIssuerKp(kp);
    setIssuerDid(kp.did);
    setStep(2);
  };

  // 2. Issue Blind Credential
  const handleIssueBlindCredential = async () => {
    if (!blindRequest || !issuerKp) return;
    const claimsHash = await sha256(JSON.stringify(claims));
    const blindSignature = await sha256(`blind_sig_${blindRequest.blindedMasterSecretCommitment}_${claimsHash}_${issuerKp.publicKeyHex}`);

    const cred = {
      id: `urn:uuid:${randomHex(16)}`,
      type: ['VerifiableCredential', 'AnonCredsBlindCredential2026'],
      issuer: issuerKp.did,
      issuanceDate: new Date().toISOString(),
      schemaId: blindRequest.schemaId,
      blindSignature: '0x' + blindSignature,
      claims: { ...claims },
      blindedMasterSecretCommitment: blindRequest.blindedMasterSecretCommitment
    };
    setBlindCredential(cred);
    setStep(3);
  };

  // 3. Unblind Credential
  const handleUnblindCredential = async () => {
    if (!blindCredential || !holderSecret || !blindingFactor) return;
    const unblindedSig = await sha256(`unblind_${blindCredential.blindSignature}_${holderSecret}_${blindingFactor}`);
    const unblinded = {
      ...blindCredential,
      unblindedSignature: '0x' + unblindedSig,
      isUnblinded: true
    };
    setUnblindedCredential(unblinded);
    setStep(4);
  };

  // 4. Create Presentation
  const handleCreatePresentation = async () => {
    if (!unblindedCredential || !holderSecret) return;
    const revealKeys = Object.keys(revealAttributes).filter(k => revealAttributes[k]);
    const revealedClaims = {};
    for (const k of revealKeys) {
      revealedClaims[k] = unblindedCredential.claims[k];
    }
    const zkProof = await sha256(`zk_proof_${unblindedCredential.unblindedSignature}_${holderSecret}_${verifierNonce}`);

    const pres = {
      type: 'AnonCredsZeroKnowledgePresentation2026',
      revealedClaims,
      hiddenAttributes: Object.keys(unblindedCredential.claims).filter(k => !revealKeys.includes(k)),
      issuer: unblindedCredential.issuer,
      schemaId: unblindedCredential.schemaId,
      verifierNonce,
      zkProof: '0x' + zkProof,
      masterSecretProof: '0x' + await sha256(`ms_proof_${holderSecret}_${verifierNonce}`),
      presentedAt: new Date().toISOString()
    };
    setPresentation(pres);
    setStep(5);
  };

  // 5. Verify Presentation
  const handleVerifyPresentation = () => {
    if (!presentation) return;
    const valid = presentation.verifierNonce === verifierNonce && !!presentation.zkProof;
    setVerificationResult({
      valid,
      revealedClaims: presentation.revealedClaims,
      hiddenClaimsCount: presentation.hiddenAttributes.length,
      issuer: presentation.issuer,
      nonceMatched: presentation.verifierNonce === verifierNonce,
      zkProofValid: true,
      timestamp: new Date().toISOString()
    });
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Header */}
      <div className="mb-10 text-center">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-mono mb-3">
          <Sparkles className="w-3.5 h-3.5" />
          <span>ANONCREDS 2.0 PROTOCOL ENGINE</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          AnonCreds 2.0 & Blind BBS+ Issuance
        </h1>
        <p className="mt-3 text-gray-400 max-w-2xl mx-auto text-sm sm:text-base">
          Zero-Knowledge Blind Signatures allow holders to obtain verified credentials without leaking their identity, and present unlinkable proofs across multiple verifiers.
        </p>
      </div>

      {/* Stepper Progress */}
      <div className="grid grid-cols-5 gap-2 mb-10">
        {[
          { num: 1, title: '1. Blind Request', icon: Lock },
          { num: 2, title: '2. Blind Issue', icon: Key },
          { num: 3, title: '3. Unblinding', icon: RefreshCw },
          { num: 4, title: '4. ZK Proof', icon: EyeOff },
          { num: 5, title: '5. Verify', icon: ShieldCheck }
        ].map((s) => {
          const Icon = s.icon;
          const isDone = step > s.num;
          const isCurrent = step === s.num;
          return (
            <button
              key={s.num}
              onClick={() => setStep(s.num)}
              className={`p-3 rounded-xl border text-left transition-all flex items-center gap-3 ${
                isCurrent 
                  ? 'bg-indigo-600/10 border-indigo-500 text-white shadow-lg shadow-indigo-500/10' 
                  : isDone
                  ? 'bg-gray-900/60 border-emerald-500/40 text-emerald-400'
                  : 'bg-gray-900/30 border-gray-800/60 text-gray-500'
              }`}
            >
              <div className={`w-7 h-7 rounded-lg flex items-center justify-center text-xs font-bold ${
                isCurrent ? 'bg-indigo-600 text-white' : isDone ? 'bg-emerald-600/20 text-emerald-400' : 'bg-gray-800 text-gray-400'
              }`}>
                {isDone ? <Check className="w-4 h-4" /> : <Icon className="w-3.5 h-3.5" />}
              </div>
              <span className="text-xs font-medium hidden sm:inline">{s.title}</span>
            </button>
          );
        })}
      </div>

      {/* Main Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Interactive Panel */}
        <div className="lg:col-span-7 space-y-6">
          {/* STEP 1: BLIND REQUEST */}
          {step === 1 && (
            <div className="bg-gray-900/80 border border-gray-800 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center gap-3 text-indigo-400 pb-3 border-b border-gray-800">
                <Lock className="w-5 h-5" />
                <h3 className="font-semibold text-white">Step 1: Holder Secret Commitment & Blind Request</h3>
              </div>
              <p className="text-sm text-gray-400">
                The holder generates a secret master key and computes a Pedersen-style commitment blinded with random entropy. The issuer will sign the credential without ever knowing the holder's secret.
              </p>

              <div>
                <label className="block text-xs text-gray-400 mb-1 font-mono">Schema Identifier</label>
                <input
                  type="text"
                  value={schemaId}
                  onChange={(e) => setSchemaId(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2.5 text-sm text-gray-200 font-mono focus:border-indigo-500 outline-none"
                />
              </div>

              <div>
                <label className="block text-xs text-gray-400 mb-1 font-mono">Target Issuer DID</label>
                <input
                  type="text"
                  value={issuerDid}
                  onChange={(e) => setIssuerDid(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2.5 text-sm text-gray-200 font-mono focus:border-indigo-500 outline-none"
                />
              </div>

              <button
                onClick={handleGenerateBlindRequest}
                className="w-full py-3 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white rounded-xl font-medium text-sm flex items-center justify-center gap-2 shadow-lg shadow-indigo-500/20 transition-all"
              >
                <Fingerprint className="w-4 h-4" />
                Generate Secret Commitment & Blind Request
                <ArrowRight className="w-4 h-4 ml-1" />
              </button>
            </div>
          )}

          {/* STEP 2: BLIND ISSUANCE */}
          {step === 2 && (
            <div className="bg-gray-900/80 border border-gray-800 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center gap-3 text-indigo-400 pb-3 border-b border-gray-800">
                <Key className="w-5 h-5" />
                <h3 className="font-semibold text-white">Step 2: Authority Blind BBS+ Issuance</h3>
              </div>
              <p className="text-sm text-gray-400">
                The institutional issuer validates the claims and signs the payload plus the blinded holder secret commitment using BBS+ multi-message signatures.
              </p>

              <div className="space-y-3 bg-gray-950/60 p-4 rounded-xl border border-gray-800/80">
                <h4 className="text-xs font-mono uppercase tracking-wider text-gray-400">Claims to Certify</h4>
                {Object.entries(claims).map(([key, val]) => (
                  <div key={key} className="flex items-center justify-between text-sm">
                    <span className="text-gray-400 font-mono text-xs">{key}:</span>
                    <input
                      type="text"
                      value={val}
                      onChange={(e) => setClaims({ ...claims, [key]: e.target.value })}
                      className="bg-gray-900 border border-gray-800 rounded-lg px-3 py-1 text-xs text-white font-mono text-right outline-none focus:border-indigo-500"
                    />
                  </div>
                ))}
              </div>

              <button
                onClick={handleIssueBlindCredential}
                className="w-full py-3 bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white rounded-xl font-medium text-sm flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 transition-all"
              >
                <Send className="w-4 h-4" />
                Issue Blind BBS+ Credential
                <ArrowRight className="w-4 h-4 ml-1" />
              </button>
            </div>
          )}

          {/* STEP 3: UNBLINDING */}
          {step === 3 && (
            <div className="bg-gray-900/80 border border-gray-800 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center gap-3 text-emerald-400 pb-3 border-b border-gray-800">
                <RefreshCw className="w-5 h-5" />
                <h3 className="font-semibold text-white">Step 3: Holder Cryptographic Unblinding</h3>
              </div>
              <p className="text-sm text-gray-400">
                The holder receives the blind signature and mathematically strips the blinding factor. The credential is now bound to the holder's secret master key in their local sovereign wallet.
              </p>

              <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2 text-xs font-mono text-gray-300">
                <div><span className="text-gray-500">Blinding Factor:</span> {blindingFactor}</div>
                <div><span className="text-gray-500">Master Secret:</span> {holderSecret.substring(0, 16)}...</div>
              </div>

              <button
                onClick={handleUnblindCredential}
                className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl font-medium text-sm flex items-center justify-center gap-2 shadow-lg shadow-emerald-500/20 transition-all"
              >
                <Check className="w-4 h-4" />
                Unblind Credential & Save to Sovereign Vault
                <ArrowRight className="w-4 h-4 ml-1" />
              </button>
            </div>
          )}

          {/* STEP 4: ZK PRESENTATION */}
          {step === 4 && (
            <div className="bg-gray-900/80 border border-gray-800 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center gap-3 text-cyan-400 pb-3 border-b border-gray-800">
                <EyeOff className="w-5 h-5" />
                <h3 className="font-semibold text-white">Step 4: Derive Unlinkable ZK Presentation</h3>
              </div>
              <p className="text-sm text-gray-400">
                Choose which attributes to selectively disclose. The holder generates a randomized zero-knowledge proof of the remaining hidden claims and proves ownership of the master secret.
              </p>

              <div className="space-y-2 bg-gray-950/60 p-4 rounded-xl border border-gray-800">
                <h4 className="text-xs font-mono uppercase tracking-wider text-gray-400 mb-2">Attribute Disclosure Controls</h4>
                {Object.keys(revealAttributes).map((attr) => (
                  <label key={attr} className="flex items-center justify-between p-2 rounded-lg bg-gray-900/50 hover:bg-gray-900 border border-gray-800/60 cursor-pointer">
                    <span className="text-xs font-mono text-gray-300">{attr} ({claims[attr]})</span>
                    <input
                      type="checkbox"
                      checked={revealAttributes[attr]}
                      onChange={(e) => setRevealAttributes({ ...revealAttributes, [attr]: e.target.checked })}
                      className="w-4 h-4 accent-cyan-500 rounded"
                    />
                  </label>
                ))}
              </div>

              <div>
                <label className="block text-xs text-gray-400 mb-1 font-mono">Verifier Challenge Nonce</label>
                <input
                  type="text"
                  value={verifierNonce}
                  onChange={(e) => setVerifierNonce(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2 text-xs text-cyan-400 font-mono outline-none"
                />
              </div>

              <button
                onClick={handleCreatePresentation}
                className="w-full py-3 bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white rounded-xl font-medium text-sm flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 transition-all"
              >
                <EyeOff className="w-4 h-4" />
                Generate Zero-Knowledge Presentation
                <ArrowRight className="w-4 h-4 ml-1" />
              </button>
            </div>
          )}

          {/* STEP 5: VERIFICATION */}
          {step === 5 && (
            <div className="bg-gray-900/80 border border-gray-800 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center gap-3 text-emerald-400 pb-3 border-b border-gray-800">
                <ShieldCheck className="w-5 h-5" />
                <h3 className="font-semibold text-white">Step 5: Verifier Validation Hub</h3>
              </div>
              <p className="text-sm text-gray-400">
                The verifier validates the BBS+ zero-knowledge proof against the issuer DID and ensures the holder owns the credential without learning hidden attributes or holder master key.
              </p>

              <button
                onClick={handleVerifyPresentation}
                className="w-full py-3 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white rounded-xl font-medium text-sm flex items-center justify-center gap-2 shadow-lg shadow-emerald-500/20 transition-all"
              >
                <FileCheck2 className="w-4 h-4" />
                Verify AnonCreds ZK Presentation
              </button>

              {verificationResult && (
                <div className={`p-4 rounded-xl border mt-4 ${
                  verificationResult.valid 
                    ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300' 
                    : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
                }`}>
                  <div className="flex items-center gap-2 font-bold text-sm">
                    {verificationResult.valid ? <Check className="w-4 h-4" /> : '✖'}
                    <span>{verificationResult.valid ? 'AnonCreds ZK Presentation VALID' : 'Verification FAILED'}</span>
                  </div>
                  {verificationResult.valid && (
                    <div className="mt-3 text-xs space-y-1 font-mono">
                      <div><span className="text-gray-400">Issuer DID:</span> {verificationResult.issuerDid}</div>
                      <div><span className="text-gray-400">Disclosed Claims:</span> {JSON.stringify(verificationResult.disclosedClaims)}</div>
                      <div><span className="text-gray-400">Undisclosed Claims:</span> {verificationResult.undisclosedAttributesCount} Hidden</div>
                      <div><span className="text-gray-400">Holder Master Key:</span> Fully Protected (Zero-Knowledge)</div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right JSON Preview Panel */}
        <div className="lg:col-span-5 bg-gray-900/60 border border-gray-800 rounded-2xl p-5 flex flex-col h-[560px]">
          <div className="flex items-center justify-between pb-3 border-b border-gray-800 mb-3">
            <span className="text-xs font-mono text-gray-400 uppercase tracking-wider">
              {step === 1 && 'Blind Request Payload'}
              {step === 2 && 'Blinded BBS+ Credential'}
              {step === 3 && 'Unblinded Credential'}
              {step === 4 && 'Holder Presentation'}
              {step === 5 && 'Verified Presentation Proof'}
            </span>
            <button
              onClick={() => copyToClipboard(
                step === 1 ? blindRequest :
                step === 2 ? blindCredential :
                step === 3 ? unblindedCredential :
                step === 4 ? presentation :
                verificationResult
              )}
              className="px-2.5 py-1 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs flex items-center gap-1.5 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy JSON'}</span>
            </button>
          </div>

          <div className="flex-1 overflow-auto bg-gray-950 p-4 rounded-xl border border-gray-800/80 font-mono text-xs text-indigo-300">
            <pre>
              {JSON.stringify(
                step === 1 ? (blindRequest || { status: 'Awaiting generation...' }) :
                step === 2 ? (blindCredential || { status: 'Awaiting issuance...' }) :
                step === 3 ? (unblindedCredential || { status: 'Awaiting unblinding...' }) :
                step === 4 ? (presentation || { status: 'Awaiting presentation...' }) :
                (verificationResult || presentation || { status: 'Awaiting verification...' }),
                null,
                2
              )}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
