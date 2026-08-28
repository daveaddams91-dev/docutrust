import React, { useState, useEffect } from 'react';
import { 
  Cpu, 
  Play, 
  RotateCcw, 
  CheckCircle2, 
  Layers, 
  Lock, 
  Terminal, 
  Hash, 
  QrCode, 
  ShieldCheck,
  ArrowRight,
  ChevronRight
} from 'lucide-react';

export default function ProtocolSimulator() {
  const [currentStage, setCurrentStage] = useState(1);
  const [isPlaying, setIsPlaying] = useState(false);
  const [logs, setLogs] = useState([
    '[INIT] DocuTrust Simulation Engine v1.0 initialized',
    '[READY] Ready to simulate full lifecycle of sovereign credential'
  ]);

  const stages = [
    {
      id: 1,
      title: 'Data Ingestion & JCS Canonicalization',
      desc: 'Recipient claims are formatted and canonicalized using RFC 8785 (JCS) to produce a deterministic byte sequence.',
      icon: Layers,
      color: 'text-blue-400',
      actionLog: '[STAGE 1] Ingested recipient metadata. Normalized to RFC 8785 canonical JSON.'
    },
    {
      id: 2,
      title: 'Asymmetric Ed25519 Authority Signing',
      desc: 'The institutional private key computes a 64-byte Ed25519 digital signature over the SHA-256 canonical hash.',
      icon: Lock,
      color: 'text-indigo-400',
      actionLog: '[STAGE 2] Generated 64-byte Ed25519 signature: 0x8f2c...3a4b with DID did:key:z6Mk...'
    },
    {
      id: 3,
      title: 'Merkle Tree Construction',
      desc: 'Batch leaves are hashed with domain separation (0x00 leaf, 0x01 node) to form a tamper-proof binary Merkle Tree.',
      icon: Hash,
      color: 'text-purple-400',
      actionLog: '[STAGE 3] Built binary Merkle tree with RFC 6962 domain separation. Merkle Root: 0xe9c3...9184'
    },
    {
      id: 4,
      title: 'Public Ledger Anchor Finalization',
      desc: 'The 32-byte Merkle root is committed to an immutable public blockchain ledger (Polygon/Ethereum) with a cryptographic timestamp.',
      icon: ShieldCheck,
      color: 'text-cyan-400',
      actionLog: '[STAGE 4] Committed Merkle root to Polygon Mainnet. Tx: 0x71c8...3d34 | Block: #54890210'
    },
    {
      id: 5,
      title: 'Visual Rendering & QR Code Seal',
      desc: 'A high-resolution tamper-evident certificate is rendered with an embedded QR code containing the verification URL and compact proof.',
      icon: QrCode,
      color: 'text-amber-400',
      actionLog: '[STAGE 5] Encoded QR verification payload and generated SVG certificate.'
    },
    {
      id: 6,
      title: 'Independent 3rd-Party Verification',
      desc: 'An employer or verifier scans the QR code, extracts the public key from the issuer DID, and verifies the math in sub-50ms.',
      icon: CheckCircle2,
      color: 'text-emerald-400',
      actionLog: '[STAGE 6] Third-party verification successful. Signature valid, anchor confirmed. Audit time: 0.04ms.'
    }
  ];

  const advanceStage = (target) => {
    const next = target || (currentStage < 6 ? currentStage + 1 : 1);
    setCurrentStage(next);
    setLogs(prev => [...prev, stages[next - 1].actionLog]);
  };

  useEffect(() => {
    let interval;
    if (isPlaying) {
      interval = setInterval(() => {
        setCurrentStage(curr => {
          if (curr >= 6) {
            setIsPlaying(false);
            return 6;
          }
          const next = curr + 1;
          setLogs(prev => [...prev, stages[next - 1].actionLog]);
          return next;
        });
      }, 1500);
    }
    return () => clearInterval(interval);
  }, [isPlaying]);

  const resetSimulator = () => {
    setCurrentStage(1);
    setIsPlaying(false);
    setLogs([
      '[RESET] Simulator reset to initial state.',
      '[STAGE 1] Ingested recipient metadata. Normalized to RFC 8785 canonical JSON.'
    ]);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 text-left">
      {/* Header */}
      <div className="mb-10 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-2 uppercase tracking-widest">
            <Cpu className="w-3.5 h-3.5" />
            <span>Interactive Protocol Node Sandbox</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            Cryptographic Protocol Simulator
          </h2>
          <p className="text-sm text-gray-400 mt-2">
            Step through each phase of the sovereign trust lifecycle to see how raw student identity transforms into a mathematical blockchain proof.
          </p>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider shadow-lg shadow-blue-600/30 transition-all"
          >
            <Play className="w-3.5 h-3.5" />
            {isPlaying ? 'Pause Protocol' : 'Auto-Run Protocol'}
          </button>
          <button
            onClick={resetSimulator}
            className="p-2.5 rounded-xl bg-gray-900 border border-gray-800 text-gray-400 hover:text-white transition-colors"
            title="Reset Simulator"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Progress Stage Tracker */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-8">
        {stages.map(stage => {
          const Icon = stage.icon;
          const isActive = currentStage === stage.id;
          const isCompleted = currentStage > stage.id;

          return (
            <div
              key={stage.id}
              onClick={() => advanceStage(stage.id)}
              className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                isActive
                  ? 'bg-blue-600/20 border-blue-500 shadow-md shadow-blue-500/20 scale-[1.02]'
                  : isCompleted
                  ? 'bg-gray-900/80 border-emerald-500/40 text-emerald-400'
                  : 'bg-gray-950/60 border-gray-800 text-gray-500 opacity-60 hover:opacity-100'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-mono uppercase">Phase 0{stage.id}</span>
                {isCompleted && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />}
              </div>
              <Icon className={`w-5 h-5 mb-1.5 ${isActive ? stage.color : isCompleted ? 'text-emerald-400' : 'text-gray-500'}`} />
              <div className="text-xs font-bold text-white truncate">{stage.title.split(' ')[0]}</div>
            </div>
          );
        })}
      </div>

      {/* Main Active Stage Deep Dive */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Active Stage Visualizer */}
        <div className="lg:col-span-7 glass-card p-6 sm:p-8 rounded-2xl border border-blue-500/30 space-y-6">
          <div className="flex items-center justify-between">
            <span className="px-3 py-1 rounded-full text-xs font-mono bg-blue-500/10 text-blue-400 border border-blue-500/30 uppercase">
              Current Stage: 0{currentStage} of 06
            </span>
            <button
              onClick={() => advanceStage()}
              className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 font-semibold"
            >
              Next Phase <ChevronRight className="w-4 h-4" />
            </button>
          </div>

          <div>
            <h3 className="text-2xl font-bold text-white mb-2">
              {stages[currentStage - 1].title}
            </h3>
            <p className="text-sm text-gray-300 leading-relaxed">
              {stages[currentStage - 1].desc}
            </p>
          </div>

          {/* Interactive Stage Specific Render */}
          <div className="p-6 rounded-xl bg-gray-950 border border-gray-800 font-mono text-xs space-y-3">
            {currentStage === 1 && (
              <div className="space-y-2">
                <div className="text-gray-500 text-[11px]">JCS CANONICAL NORMALIZATION (RFC 8785)</div>
                <div className="p-3 bg-black rounded-lg text-emerald-400 text-[11px] overflow-x-auto">
                  {`{"@context":["https://www.w3.org/ns/credentials/v2"],"credentialSubject":{"degree":"M.Sc. CS","name":"Alex Rivera"},"id":"urn:uuid:7f3b...","issuer":{"id":"did:key:z6Mk..."},"type":["VerifiableCredential"]}`}
                </div>
              </div>
            )}

            {currentStage === 2 && (
              <div className="space-y-2">
                <div className="text-gray-500 text-[11px]">ED25519 ASYMMETRIC SIGNATURE</div>
                <div className="text-white text-xs">Authority DID: <span className="text-indigo-400">did:key:z6MkuG2B83x1K8u4W7q2V6m...</span></div>
                <div className="p-3 bg-black rounded-lg text-blue-300 text-[11px] break-all">
                  0x8f2c3b4e5d6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d
                </div>
              </div>
            )}

            {currentStage === 3 && (
              <div className="space-y-2">
                <div className="text-gray-500 text-[11px]">MERKLE TREE ROOT & INCLUSION AUDIT PATH</div>
                <div className="text-purple-400 font-bold">Merkle Root: 0xe9c3140a82b17f549184...</div>
                <div className="text-gray-400 text-[11px]">Audit Path: [Left: 0x4a1b..., Right: 0x9e12...]</div>
              </div>
            )}

            {currentStage === 4 && (
              <div className="space-y-2">
                <div className="text-gray-500 text-[11px]">LEDGER ANCHOR RECEIPT (POLYGON)</div>
                <div className="text-cyan-300">Transaction: 0x71c8a185676f18167341829e9241b777a83b3d34...</div>
                <div className="text-gray-400">Block: #54890210 • Confirmations: 128 • Status: Finalized</div>
              </div>
            )}

            {currentStage === 5 && (
              <div className="space-y-2 text-center py-2">
                <QrCode className="w-16 h-16 text-amber-400 mx-auto mb-2" />
                <div className="text-white text-xs font-bold">Verification URL with Compact Proof Generated</div>
                <div className="text-gray-500 text-[10px]">https://docutrust.org/verify?id=urn:uuid:7f3b89e1...</div>
              </div>
            )}

            {currentStage === 6 && (
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                  <CheckCircle2 className="w-4 h-4" /> Real-Time Third-Party Verification
                </div>
                <div className="text-gray-300 text-xs">Verifier: Employer HR System / Background Check Bot</div>
                <div className="text-emerald-400 text-xs">Result: 100% Authentic • 0 Tampering • Zero Network Latency</div>
              </div>
            )}
          </div>
        </div>

        {/* Live Simulation Terminal Console */}
        <div className="lg:col-span-5 glass-card p-6 rounded-2xl border border-gray-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-gray-800 mb-4">
              <span className="text-xs font-mono text-gray-400 uppercase flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-blue-400" />
                Simulated Node Telemetry
              </span>
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            </div>

            <div className="bg-black p-4 rounded-xl border border-gray-800 font-mono text-[11px] text-gray-300 space-y-2 max-h-80 overflow-y-auto">
              {logs.map((log, index) => (
                <div key={index} className="leading-relaxed">
                  <span className="text-gray-600">[{index + 1}]</span>{' '}
                  <span className={log.includes('STAGE') ? 'text-blue-400 font-bold' : log.includes('RESET') ? 'text-rose-400' : 'text-gray-300'}>
                    {log}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="pt-4 mt-4 border-t border-gray-800 text-xs font-mono text-gray-500 flex items-center justify-between">
            <span>Node Consensus: 100%</span>
            <span>Memory: 18.4 MB</span>
          </div>
        </div>
      </div>
    </div>
  );
}
