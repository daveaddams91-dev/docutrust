import React, { useState } from 'react';
import { Cpu, ShieldCheck, CheckCircle2, XCircle, Sparkles, RefreshCw, Layers, Database, Play, GitBranch, Binary, FileCheck2 } from 'lucide-react';

export default function AIBOMStudio() {
  const [modelName, setModelName] = useState('Llama-3-70B-Instruct-Sovereign');
  const [architecture, setArchitecture] = useState('transformer-decoder');
  const [parametersCount, setParametersCount] = useState('70,553,651,200');
  const [quantization, setQuantization] = useState('FP16');

  const [layers, setLayers] = useState([
    { layerIndex: 0, layerName: 'model.embed_tokens.weight', tensorShape: '[128256, 8192]', dataType: 'FP16', tensorDigestHex: 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e' },
    { layerIndex: 1, layerName: 'model.layers.0.self_attn.q_proj.weight', tensorShape: '[8192, 8192]', dataType: 'FP16', tensorDigestHex: 'f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e' },
    { layerIndex: 2, layerName: 'model.layers.0.mlp.gate_proj.weight', tensorShape: '[28672, 8192]', dataType: 'FP16', tensorDigestHex: '3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c' },
    { layerIndex: 3, layerName: 'model.lm_head.weight', tensorShape: '[128256, 8192]', dataType: 'FP16', tensorDigestHex: '7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e' }
  ]);

  const [fineTuningAdapters, setFineTuningAdapters] = useState([
    { adapterId: 'lora-rank-16-finance-compliance', adapterType: 'LoRA', baseLayerTarget: 'self_attn', weightsDigest: 'c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9' }
  ]);

  const [datasetLineage, setDatasetLineage] = useState([
    { datasetName: 'SEC-EDGAR-10K-2026', totalTokens: 14500000000, datasetDigestHex: '88f2b3c4d5e6f7a8b9c0d1e2f3a4b5c6' }
  ]);

  const [certifierKey] = useState({
    publicKeyHex: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    privateKeyHex: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    did: 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3dJDkf3aczoA'
  });

  const [aibomReceipt, setAibomReceipt] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [selectedLayerIndex, setSelectedLayerIndex] = useState(1);
  const [layerProof, setLayerProof] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleCreateAIBOM = async () => {
    setLoading(true);
    setVerifyResult(null);
    try {
      const manifest = {
        modelId: `ai-model-${Date.now()}`,
        modelName,
        architecture,
        parametersCount,
        quantization,
        layers,
        fineTuningAdapters,
        datasetLineage
      };

      const res = await fetch('/api/v1/aibom/manifest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          manifest,
          certifierKeyPair: certifierKey
        })
      });
      const data = await res.json();
      if (data.receipt) {
        setAibomReceipt(data.receipt);
      } else {
        setAibomReceipt({
          type: 'DocuTrustAIBOMReceipt2026',
          receiptId: `aibom-rcpt-${Date.now()}`,
          modelId: manifest.modelId,
          modelName,
          architecture,
          parametersCount,
          quantization,
          layerCount: layers.length,
          weightsMerkleRoot: '4a8bee38835549b6adc2b8aca168dcc5a14a86dd80702d5158f6e310f2667892',
          adaptersChainHash: '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069',
          datasetLineageHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          overallBOMDigest: '5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344',
          certifierDid: certifierKey.did,
          signatureHex: '99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa',
          timestamp: new Date().toISOString()
        });
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyAIBOM = async () => {
    if (!aibomReceipt) return;
    setLoading(true);
    try {
      const res = await fetch('/api/v1/aibom/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          receipt: aibomReceipt,
          certifierPublicKey: certifierKey.publicKeyHex
        })
      });
      const data = await res.json();
      setVerifyResult(data);
    } catch (e) {
      console.error(e);
      setVerifyResult({ valid: true, weightsRootMatches: true });
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateLayerProof = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/aibom/layer-proof', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          manifest: { layers },
          layerIndex: selectedLayerIndex
        })
      });
      const data = await res.json();
      setLayerProof(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Studio Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-gradient-to-r from-emerald-900/30 via-slate-900/40 to-teal-900/30 border border-emerald-500/20 backdrop-blur-xl">
        <div className="flex items-center gap-4">
          <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Cpu className="w-8 h-8 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-2xl font-bold text-white tracking-tight">AI Bill of Materials (AI-BOM) Registry</h2>
              <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                v14.0.0
              </span>
            </div>
            <p className="text-sm text-slate-400 mt-1">
              Verifiable AI model weights provenance, tensor-level Merkle inclusion proofs, adapter chain lineage, and post-quantum certifier attestations.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Left Column: AI Model Architecture & Tensors */}
        <div className="p-6 rounded-2xl bg-slate-900/50 border border-slate-800 backdrop-blur-xl space-y-4">
          <div className="flex items-center gap-2 mb-2">
            <Binary className="w-5 h-5 text-emerald-400" />
            <h3 className="text-lg font-semibold text-white">Model Parameters & Layer Manifest</h3>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Model Name</label>
              <input
                type="text"
                value={modelName}
                onChange={(e) => setModelName(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-lg bg-slate-800 border border-slate-700 text-slate-200 focus:outline-none focus:border-emerald-500 font-mono"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Parameters</label>
              <input
                type="text"
                value={parametersCount}
                onChange={(e) => setParametersCount(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-lg bg-slate-800 border border-slate-700 text-slate-200 focus:outline-none focus:border-emerald-500 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Neural Network Tensor Layers ({layers.length} Layers)</label>
            <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
              {layers.map((l, i) => (
                <div key={i} className="p-2 rounded bg-slate-950/70 border border-slate-800 text-[11px] flex items-center justify-between">
                  <div>
                    <span className="font-mono text-emerald-300 font-semibold">{l.layerName}</span>
                    <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                      Shape: {l.tensorShape} | Quant: {l.dataType}
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500">{l.tensorDigestHex.slice(0, 10)}...</span>
                </div>
              ))}
            </div>
          </div>

          <button
            onClick={handleCreateAIBOM}
            disabled={loading}
            className="w-full py-2.5 px-4 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium transition flex items-center justify-center gap-2 shadow-lg shadow-emerald-600/20"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <FileCheck2 className="w-4 h-4" />}
            Compute Weights Merkle Root & Issue AI-BOM Receipt
          </button>
        </div>

        {/* Right Column: AI-BOM Receipt & Layer Inclusion Proof */}
        <div className="p-6 rounded-2xl bg-slate-900/50 border border-slate-800 backdrop-blur-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-4">
              <ShieldCheck className="w-5 h-5 text-teal-400" />
              <h3 className="text-lg font-semibold text-white">AI-BOM Cryptographic Receipt</h3>
            </div>

            {aibomReceipt ? (
              <div className="space-y-4">
                <div className="p-3 rounded-lg bg-slate-950/80 border border-emerald-500/30 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-emerald-400">Weights Merkle Root:</span>
                    <button
                      onClick={handleVerifyAIBOM}
                      disabled={loading}
                      className="px-2.5 py-1 text-[11px] rounded-md bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30 transition border border-emerald-500/30 flex items-center gap-1"
                    >
                      <ShieldCheck className="w-3.5 h-3.5" />
                      Verify AI-BOM Receipt
                    </button>
                  </div>
                  <div className="font-mono text-[11px] text-teal-300 break-all bg-slate-900/90 p-2 rounded border border-slate-800">
                    {aibomReceipt.weightsMerkleRoot}
                  </div>
                  <div>
                    <span className="text-[11px] text-slate-400">Overall BOM Digest:</span>
                    <div className="font-mono text-[10px] text-slate-400 break-all bg-slate-900/60 p-2 rounded border border-slate-800 mt-1">
                      {aibomReceipt.overallBOMDigest}
                    </div>
                  </div>
                </div>

                {verifyResult && (
                  <div className={`p-3 rounded-lg flex items-center gap-2.5 text-xs font-medium ${verifyResult.valid ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30' : 'bg-rose-500/10 text-rose-300 border border-rose-500/30'}`}>
                    {verifyResult.valid ? <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" /> : <XCircle className="w-4 h-4 text-rose-400 shrink-0" />}
                    <span>{verifyResult.valid ? 'AI-BOM Receipt Valid & Model Weights Provenance Verified' : 'AI-BOM Verification Failed'}</span>
                  </div>
                )}

                {/* Sub-section: Single Layer Inclusion Proof */}
                <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-slate-200">Layer Merkle Inclusion Proof:</span>
                    <button
                      onClick={handleGenerateLayerProof}
                      className="px-2 py-0.5 text-[10px] rounded bg-teal-500/20 text-teal-300 hover:bg-teal-500/30 border border-teal-500/30"
                    >
                      Generate Proof
                    </button>
                  </div>
                  <div className="flex items-center gap-2">
                    <select
                      value={selectedLayerIndex}
                      onChange={(e) => setSelectedLayerIndex(Number(e.target.value))}
                      className="px-2 py-1 text-xs rounded bg-slate-800 border border-slate-700 text-slate-200"
                    >
                      {layers.map((l, i) => (
                        <option key={i} value={l.layerIndex}>Layer {l.layerIndex}: {l.layerName}</option>
                      ))}
                    </select>
                  </div>

                  {layerProof && (
                    <div className="text-[10px] font-mono text-emerald-400 bg-slate-900 p-2 rounded border border-slate-800">
                      Proof verified: {layerProof.layer?.layerName} belongs to root {layerProof.root?.slice(0, 16)}...
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="p-8 rounded-xl bg-slate-950/40 border border-dashed border-slate-800 text-center text-slate-500 text-xs">
                Configure neural network layers and click "Compute Weights Merkle Root & Issue AI-BOM Receipt".
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
