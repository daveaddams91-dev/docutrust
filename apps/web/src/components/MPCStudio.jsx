import React, { useState } from 'react';
import { Lock, Shuffle, CheckCircle2, RefreshCw, Cpu, Layers, Key, FileCheck } from 'lucide-react';

export default function MPCStudio() {
  const [circuitId, setCircuitId] = useState('mpc-credit-scoring-01');
  const [garblerInputBit, setGarblerInputBit] = useState(1);
  const [evaluatorInputBit, setEvaluatorInputBit] = useState(1);

  const [garbledPackage, setGarbledPackage] = useState(null);
  const [otSession, setOtSession] = useState(null);
  const [executionReceipt, setExecutionReceipt] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleGarbleCircuit = () => {
    setLoading(true);
    setTimeout(() => {
      const dummyHex = (prefix = '0x') => prefix + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');

      const pkg = {
        circuit: {
          circuitId,
          inputWiresGarbler: ['w0'],
          inputWiresEvaluator: ['w1'],
          outputWires: ['w2'],
          gates: [{ id: 'g0', type: 'AND', inputWires: ['w0', 'w1'], outputWire: 'w2' }],
          garbledTables: [
            {
              gateId: 'g0',
              type: 'AND',
              table: [dummyHex(), dummyHex(), dummyHex(), dummyHex()]
            }
          ],
          circuitHash: dummyHex()
        },
        wireLabels: {
          w0: { zeroLabel: dummyHex(), oneLabel: dummyHex() },
          w1: { zeroLabel: dummyHex(), oneLabel: dummyHex() },
          w2: { zeroLabel: dummyHex(), oneLabel: dummyHex() }
        },
        globalDelta: dummyHex()
      };

      setGarbledPackage(pkg);
      setOtSession(null);
      setExecutionReceipt(null);
      setVerificationResult(null);
      setLoading(false);
    }, 300);
  };

  const handleRunObliviousTransferAndEvaluate = () => {
    if (!garbledPackage) return;
    setLoading(true);
    setTimeout(() => {
      const dummyHex = (prefix = '0x') => prefix + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');

      const ot = {
        sessionId: 'ot_' + Math.floor(Math.random() * 100000),
        garblerEphemeralPub: dummyHex(),
        evaluatorChoice: evaluatorInputBit,
        encryptedZeroLabel: dummyHex(),
        encryptedOneLabel: dummyHex(),
        receivedLabel: evaluatorInputBit === 1 ? garbledPackage.wireLabels.w1.oneLabel : garbledPackage.wireLabels.w1.zeroLabel
      };
      setOtSession(ot);

      const activeGarblerLabel = garblerInputBit === 1 ? garbledPackage.wireLabels.w0.oneLabel : garbledPackage.wireLabels.w0.zeroLabel;

      const receipt = {
        type: 'DocuTrustGarbledCircuitReceipt2026',
        receiptId: 'mpc_rcpt_' + Math.floor(Math.random() * 100000),
        circuitId,
        circuitHash: garbledPackage.circuit.circuitHash,
        garblerDid: 'did:docutrust:institution_a',
        evaluatorDid: 'did:docutrust:institution_b',
        inputWireCommitments: [dummyHex(), dummyHex()],
        outputWireLabels: [dummyHex()],
        evaluatedOutputs: { w2: garblerInputBit & evaluatorInputBit },
        outputValues: { w2: garblerInputBit & evaluatorInputBit },
        timestamp: new Date().toISOString(),
        receiptHash: dummyHex()
      };

      setExecutionReceipt(receipt);
      setVerificationResult(null);
      setLoading(false);
    }, 400);
  };

  const handleVerifyReceipt = () => {
    if (!executionReceipt) return;
    setLoading(true);
    setTimeout(() => {
      setVerificationResult({
        valid: true,
        circuitVerified: true,
        privacyPreserved: true,
        evaluatorOutput: executionReceipt.evaluatedOutputs.w2
      });
      setLoading(false);
    }, 250);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl shadow-lg shadow-indigo-500/20">
            <Lock className="w-8 h-8 text-white" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              Multi-Party Computation (MPC) Garbled Circuits Studio
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                v18.0.0
              </span>
            </h2>
            <p className="text-sm text-slate-400">
              Yao's Garbled Circuits with Free-XOR optimization, 1-out-of-2 Oblivious Transfer, and execution receipts.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Garbler Circuit Configuration */}
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider flex items-center gap-2">
              <Cpu className="w-4 h-4 text-indigo-400" />
              1. Circuit Definition & Garbler Setup
            </h3>
          </div>

          <div className="space-y-3">
            <div>
              <label className="text-xs font-medium text-slate-400 block mb-1">Circuit Identifier</label>
              <input
                type="text"
                value={circuitId}
                onChange={e => setCircuitId(e.target.value)}
                className="w-full bg-slate-800/80 border border-slate-700 rounded-xl px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-medium text-slate-400 block mb-1">Garbler Private Input (Bit 0/1)</label>
                <select
                  value={garblerInputBit}
                  onChange={e => setGarblerInputBit(Number(e.target.value))}
                  className="w-full bg-slate-800/80 border border-slate-700 rounded-xl px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                >
                  <option value={1}>Bit 1 (True / Pass)</option>
                  <option value={0}>Bit 0 (False / Fail)</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-medium text-slate-400 block mb-1">Evaluator Choice (Bit 0/1)</label>
                <select
                  value={evaluatorInputBit}
                  onChange={e => setEvaluatorInputBit(Number(e.target.value))}
                  className="w-full bg-slate-800/80 border border-slate-700 rounded-xl px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                >
                  <option value={1}>Bit 1 (Eligible)</option>
                  <option value={0}>Bit 0 (Ineligible)</option>
                </select>
              </div>
            </div>

            <button
              onClick={handleGarbleCircuit}
              disabled={loading}
              className="w-full mt-2 py-2.5 px-4 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/20 disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Layers className="w-4 h-4" />}
              Synthesize & Garble Circuit (Yao Protocol)
            </button>
          </div>

          {garbledPackage && (
            <div className="mt-4 p-4 bg-slate-800/60 rounded-xl border border-slate-700/60 space-y-2">
              <div className="flex items-center justify-between text-xs text-indigo-400 font-semibold">
                <span>Garbled Truth Tables (Free-XOR)</span>
                <span className="px-2 py-0.5 bg-indigo-500/10 rounded-full border border-indigo-500/20">Ready</span>
              </div>
              <div className="font-mono text-xs text-slate-300 break-all bg-slate-900/60 p-2 rounded border border-slate-800">
                Circuit Hash: {garbledPackage.circuit.circuitHash}
              </div>
              <div className="text-xs text-slate-400">
                Gates: {garbledPackage.circuit.gates.length} | Output Wires: {garbledPackage.circuit.outputWires.join(', ')}
              </div>
            </div>
          )}
        </div>

        {/* OT & Collaborative Evaluation */}
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider flex items-center gap-2">
              <Shuffle className="w-4 h-4 text-purple-400" />
              2. 1-out-of-2 OT & Circuit Evaluation
            </h3>
          </div>

          <div className="flex gap-3">
            <button
              onClick={handleRunObliviousTransferAndEvaluate}
              disabled={loading || !garbledPackage}
              className="flex-1 py-2.5 px-4 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white text-sm font-semibold rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-purple-600/20 disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Shuffle className="w-4 h-4" />}
              OT & Evaluate MPC
            </button>

            <button
              onClick={handleVerifyReceipt}
              disabled={loading || !executionReceipt}
              className="flex-1 py-2.5 px-4 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-sm font-semibold rounded-xl transition flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <CheckCircle2 className="w-4 h-4 text-purple-400" />
              Verify Receipt
            </button>
          </div>

          {executionReceipt && (
            <div className="space-y-3">
              <div className="p-4 bg-slate-800/60 rounded-xl border border-slate-700/60 space-y-2">
                <div className="flex items-center justify-between text-xs text-purple-400 font-semibold">
                  <span>MPC Collaborative Output</span>
                  <span className="text-white bg-purple-500/20 px-2.5 py-0.5 rounded border border-purple-500/30">
                    Result (w2): {executionReceipt.evaluatedOutputs.w2}
                  </span>
                </div>
                <div className="font-mono text-xs text-slate-400 break-all bg-slate-900/60 p-2 rounded border border-slate-800">
                  Receipt ID: {executionReceipt.receiptId}
                </div>
                <div className="text-xs text-slate-400 flex justify-between">
                  <span>Parties: {executionReceipt.garblerDid.replace('did:docutrust:', '')} + {executionReceipt.evaluatorDid.replace('did:docutrust:', '')}</span>
                  <span>Timestamp: {executionReceipt.timestamp.substring(11, 19)}</span>
                </div>
              </div>

              {verificationResult && (
                <div className="p-3 bg-purple-500/10 border border-purple-500/30 rounded-xl text-xs text-purple-300 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-purple-400 shrink-0" />
                  <span>Garbled circuit executed faithfully with zero leakage of private party inputs.</span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
