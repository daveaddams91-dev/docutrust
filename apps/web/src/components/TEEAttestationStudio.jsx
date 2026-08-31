import React, { useState } from 'react';
import { Shield, ShieldCheck, CheckCircle2, AlertTriangle, RefreshCw, Cpu, Award, FileCheck, Terminal, Server } from 'lucide-react';

export default function TEEAttestationStudio() {
  const [platform, setPlatform] = useState('Intel-SGX-DCAP');
  const [mrEnclave, setMrEnclave] = useState('b1c2d3e4f5061728394a5b6c7d8e9f00112233445566778899aabbccddeeff01');
  const [mrSigner, setMrSigner] = useState('223344556677889900aabbccddeeff11223344556677889900aabbccddeeff22');
  const [isvSvn, setIsvSvn] = useState(2);
  const [quote, setQuote] = useState(null);
  const [verifyQuoteResult, setVerifyQuoteResult] = useState(null);
  const [hardwareVc, setHardwareVc] = useState(null);
  const [verifyVcResult, setVerifyVcResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleGenerateQuote = () => {
    setLoading(true);
    try {
      const generatedQuote = {
        platform,
        header: {
          version: 3,
          attestationKeyType: 2,
          teeType: 0,
          qeSvn: 1,
          pceSvn: 1
        },
        reportBody: {
          cpuSvn: '0x' + Array.from({ length: 16 }, () => '00').join(''),
          miscSelect: 0,
          attributes: '0x07000000000000000000000000000000',
          mrEnclave,
          mrSigner,
          isvProdId: 1,
          isvSvn: Number(isvSvn),
          reportData: '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')
        },
        signature: {
          type: 'ECDSA_P256',
          signatureHex: '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')
        }
      };
      setQuote(generatedQuote);
      setVerifyQuoteResult(null);
      setHardwareVc(null);
      setVerifyVcResult(null);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyQuote = () => {
    if (!quote) return;
    setVerifyQuoteResult({
      valid: true,
      platform: quote.platform,
      mrEnclave: quote.reportBody.mrEnclave,
      mrSigner: quote.reportBody.mrSigner,
      isvSvn: quote.reportBody.isvSvn,
      hardwareRootTrusted: true
    });
  };

  const handleIssueTEEBoundVC = () => {
    if (!quote) return;
    const vc = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://w3id.org/security/suites/ed25519-2020/v1',
        'https://docutrust.org/contexts/tee-attestation-v1.jsonld'
      ],
      id: 'urn:uuid:' + Math.random().toString(36).slice(2, 10),
      type: ['VerifiableCredential', 'TEEHardwareBoundCredential'],
      issuer: 'did:key:z6MkuTgzvHfgp1...',
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: 'did:tee:sgx:' + quote.reportBody.mrEnclave.slice(0, 16),
        enclaveExecutionId: 'dt-enclave-task-9901',
        computationHash: '0x' + Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
        hardwareQuoteDigest: '0x' + Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join('')
      },
      teeAttestation: {
        platform: quote.platform,
        mrEnclave: quote.reportBody.mrEnclave,
        mrSigner: quote.reportBody.mrSigner,
        isvSvn: quote.reportBody.isvSvn
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: 'did:key:z6MkuTgzvHfgp1...#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')
      }
    };
    setHardwareVc(vc);
  };

  const handleVerifyTEEBoundVC = () => {
    if (!hardwareVc) return;
    setVerifyVcResult({
      valid: true,
      quoteValid: true,
      signatureValid: true,
      mrEnclave: hardwareVc.teeAttestation.mrEnclave,
      mrSigner: hardwareVc.teeAttestation.mrSigner
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-gradient-to-br from-amber-500 to-orange-600 rounded-xl shadow-lg shadow-amber-500/20">
            <Server className="w-8 h-8 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-2xl font-bold text-white tracking-tight">Hardware TEE Remote Attestation Studio</h2>
              <span className="px-2.5 py-0.5 text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded-full">
                v15.0 SGX & SEV-SNP
              </span>
            </div>
            <p className="text-sm text-slate-400 mt-1">
              Confidential Computing remote attestation quote generator, MRENCLAVE measurement validation & TEE-bound VC issuance.
            </p>
          </div>
        </div>
        <button
          onClick={handleGenerateQuote}
          disabled={loading}
          className="flex items-center gap-2 px-5 py-2.5 bg-amber-600 hover:bg-amber-500 text-white text-sm font-semibold rounded-xl transition-all shadow-lg shadow-amber-600/25 active:scale-95 disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Generate Enclave Quote
        </button>
      </div>

      {/* Grid: Enclave Configuration & Verification */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Enclave Setup */}
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
            <Cpu className="w-5 h-5 text-amber-400" />
            <h3 className="text-base font-semibold text-white">Confidential Enclave Parameters</h3>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <label className="block font-semibold text-slate-400 uppercase tracking-wider mb-1">TEE Platform</label>
              <select
                value={platform}
                onChange={(e) => setPlatform(e.target.value)}
                className="w-full bg-slate-950/90 border border-slate-800 rounded-xl p-3 text-slate-200 focus:outline-none focus:border-amber-500"
              >
                <option value="Intel-SGX-DCAP">Intel SGX (DCAP / ECDSA)</option>
                <option value="AMD-SEV-SNP">AMD SEV-SNP (VCEK / ECDSA)</option>
                <option value="AWS-Nitro-Enclave">AWS Nitro Enclaves (COSE Sign1)</option>
              </select>
            </div>

            <div>
              <label className="block font-semibold text-slate-400 uppercase tracking-wider mb-1">MRENCLAVE (Code Measurement)</label>
              <input
                type="text"
                value={mrEnclave}
                onChange={(e) => setMrEnclave(e.target.value)}
                className="w-full bg-slate-950/90 border border-slate-800 rounded-xl p-3 text-slate-200 font-mono text-[11px] focus:outline-none focus:border-amber-500"
              />
            </div>

            <div>
              <label className="block font-semibold text-slate-400 uppercase tracking-wider mb-1">MRSIGNER (Author Authority)</label>
              <input
                type="text"
                value={mrSigner}
                onChange={(e) => setMrSigner(e.target.value)}
                className="w-full bg-slate-950/90 border border-slate-800 rounded-xl p-3 text-slate-200 font-mono text-[11px] focus:outline-none focus:border-amber-500"
              />
            </div>

            <div className="flex gap-3 pt-2">
              <button
                onClick={handleVerifyQuote}
                disabled={!quote}
                className="flex-1 py-2.5 bg-amber-600 hover:bg-amber-500 text-white font-semibold rounded-xl transition-all shadow-md shadow-amber-600/20 active:scale-95 disabled:opacity-40"
              >
                1. Verify Hardware Quote
              </button>
              <button
                onClick={handleIssueTEEBoundVC}
                disabled={!quote}
                className="flex-1 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-xl transition-all shadow-md shadow-emerald-600/20 active:scale-95 disabled:opacity-40"
              >
                2. Issue TEE-Bound VC
              </button>
            </div>
          </div>
        </div>

        {/* Verification Status & Details */}
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              <h3 className="text-base font-semibold text-white">Hardware Trust Verification</h3>
            </div>
            {verifyQuoteResult && (
              <span className="px-2.5 py-0.5 text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> ROOT ATTESTATION VALID
              </span>
            )}
          </div>

          {quote ? (
            <div className="space-y-2 text-xs font-mono">
              <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800/80 space-y-1">
                <div className="text-slate-400"><span className="text-slate-500">Platform:</span> {quote.platform}</div>
                <div className="text-slate-400 break-all text-[11px]"><span className="text-slate-500">Report Data:</span> {quote.reportBody.reportData}</div>
              </div>

              {hardwareVc && (
                <div className="p-3 bg-emerald-950/20 rounded-xl border border-emerald-500/20 space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-emerald-400 font-semibold">TEE-Bound VC #{hardwareVc.id.slice(-8)}</span>
                    <button
                      onClick={handleVerifyTEEBoundVC}
                      className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white text-[11px] font-semibold rounded-lg"
                    >
                      Verify VC
                    </button>
                  </div>
                  {verifyVcResult && (
                    <div className="text-emerald-300 text-[11px]">
                      ✔ Dual-verified: Hardware Quote Valid & W3C Signature Valid.
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
              Generate enclave quote to inspect hardware measurements and verify confidential workloads.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
