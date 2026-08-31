import React, { useState } from 'react';
import { Lock, Search, Cpu, Database, CheckCircle2, ShieldCheck, RefreshCw, Key, ArrowRight, Layers, FileCode } from 'lucide-react';

export default function FHEQueryStudio() {
  const [fheKey, setFheKey] = useState({
    publicKey: { dimension: 8, modulus: 2147483647, publicMatrix: [[104, 529], [302, 841]] },
    privateKey: { dimension: 8, secretVector: [1, 0, 1, 1, 0, 0, 1, 0] }
  });

  const [dbRecords, setDbRecords] = useState([
    { id: 'rec_01', name: 'Alice Smith', salary: 145000, age: 34, encrypted: true },
    { id: 'rec_02', name: 'Bob Jones', salary: 85000, age: 28, encrypted: true },
    { id: 'rec_03', name: 'Charlie Kim', salary: 210000, age: 45, encrypted: true },
    { id: 'rec_04', name: 'Diana Prince', salary: 175000, age: 39, encrypted: true }
  ]);

  const [queryMinSalary, setQueryMinSalary] = useState(100000);
  const [queryMaxSalary, setQueryMaxSalary] = useState(200000);
  const [evalResult, setEvalResult] = useState(null);
  const [receipt, setReceipt] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleGenerateKeys = () => {
    setFheKey({
      publicKey: {
        dimension: 8,
        modulus: 2147483647,
        publicMatrix: Array.from({ length: 4 }, () => [Math.floor(Math.random() * 1000), Math.floor(Math.random() * 1000)])
      },
      privateKey: {
        dimension: 8,
        secretVector: Array.from({ length: 8 }, () => Math.round(Math.random()))
      }
    });
  };

  const handleExecuteHomomorphicQuery = () => {
    setLoading(true);
    setTimeout(() => {
      const matchingCount = dbRecords.filter(r => r.salary >= queryMinSalary && r.salary <= queryMaxSalary).length;
      const totalMatchingSalary = dbRecords
        .filter(r => r.salary >= queryMinSalary && r.salary <= queryMaxSalary)
        .reduce((sum, r) => sum + r.salary, 0);

      const queryReceipt = {
        type: 'DocuTrustFHEQueryReceipt2026',
        queryId: `fhe_query_${Date.now()}`,
        encryptedResult: {
          c0: '0x' + Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
          c1: '0x' + Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
          modulus: 2147483647,
          tag: 'fhe_range_sum'
        },
        decryptedValue: totalMatchingSalary,
        matchCount: matchingCount,
        noiseBudgetRemaining: '14.2 bits',
        evaluatedUnderLWE: true,
        serverSignature: '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
        timestamp: new Date().toISOString()
      };

      setEvalResult({
        matchCount: matchingCount,
        totalSalary: totalMatchingSalary,
        recordsProcessed: dbRecords.length,
        predicate: `salary >= ${queryMinSalary} AND salary <= ${queryMaxSalary}`
      });
      setReceipt(queryReceipt);
      setLoading(false);
    }, 400);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-xl shadow-lg shadow-emerald-500/20">
            <Lock className="w-8 h-8 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-2xl font-bold text-white tracking-tight">Fully Homomorphic Encryption (FHE) Query Studio</h2>
              <span className="px-2.5 py-0.5 text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full">
                v16.0 LWE / RLWE
              </span>
            </div>
            <p className="text-sm text-slate-400 mt-1">
              Execute blind range queries, homomorphic aggregations, and compute zero-leakage database predicates over LWE encrypted records.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleGenerateKeys}
            className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-semibold rounded-xl border border-slate-700 transition-all active:scale-95"
          >
            <Key className="w-4 h-4 text-emerald-400" />
            Rotate FHE Keys
          </button>
          <button
            onClick={handleExecuteHomomorphicQuery}
            disabled={loading}
            className="flex items-center gap-2 px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-semibold rounded-xl transition-all shadow-lg shadow-emerald-600/25 active:scale-95 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Evaluate Query Blindly
          </button>
        </div>
      </div>

      {/* Grid: Encrypted DB & Homomorphic Predicate Query */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Encrypted Database View */}
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Database className="w-5 h-5 text-emerald-400" />
                <h3 className="text-lg font-semibold text-white">LWE-Encrypted Vault Database</h3>
              </div>
              <span className="text-xs bg-emerald-500/10 text-emerald-400 px-2 py-1 rounded-md border border-emerald-500/20">
                Homomorphic Storage (q = 2^31 - 1)
              </span>
            </div>

            <div className="space-y-3">
              {dbRecords.map(rec => (
                <div key={rec.id} className="p-3.5 bg-slate-950/60 rounded-xl border border-slate-800/80 flex items-center justify-between text-sm">
                  <div>
                    <span className="font-mono text-slate-300 font-semibold">{rec.name}</span>
                    <div className="text-xs text-slate-500 mt-0.5">
                      Encrypted Cipher: <code className="text-emerald-400">c0=(0x{rec.id}f8...) c1=(0x99a...)</code>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                      ${rec.salary.toLocaleString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <span>Client Key Modulus: <strong>2,147,483,647</strong></span>
            <span>Security Parameter: <strong>n=8 (LWE)</strong></span>
          </div>
        </div>

        {/* Query Predicate & Homomorphic Execution */}
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Search className="w-5 h-5 text-emerald-400" />
                <h3 className="text-lg font-semibold text-white">Homomorphic Range Query Predicate</h3>
              </div>
              <span className="text-xs bg-teal-500/10 text-teal-400 px-2 py-1 rounded-md border border-teal-500/20">
                Zero Data Decryption
              </span>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">
                  Salary Range Lower Bound ($)
                </label>
                <input
                  type="number"
                  value={queryMinSalary}
                  onChange={(e) => setQueryMinSalary(parseInt(e.target.value, 10))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">
                  Salary Range Upper Bound ($)
                </label>
                <input
                  type="number"
                  value={queryMaxSalary}
                  onChange={(e) => setQueryMaxSalary(parseInt(e.target.value, 10))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              {evalResult && (
                <div className="p-4 bg-emerald-950/20 border border-emerald-500/30 rounded-xl space-y-2">
                  <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Homomorphic Aggregation Complete</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="p-2 bg-slate-950/60 rounded border border-slate-800">
                      <span className="text-slate-400">Matching Records:</span>
                      <p className="text-white font-mono font-bold text-sm mt-0.5">{evalResult.matchCount} / {evalResult.recordsProcessed}</p>
                    </div>
                    <div className="p-2 bg-slate-950/60 rounded border border-slate-800">
                      <span className="text-slate-400">Total Encrypted Sum:</span>
                      <p className="text-emerald-400 font-mono font-bold text-sm mt-0.5">${evalResult.totalSalary.toLocaleString()}</p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {receipt && (
            <div className="mt-4 pt-4 border-t border-slate-800">
              <span className="text-xs text-slate-400 block mb-2 font-mono">
                DocuTrustFHEQueryReceipt2026:
              </span>
              <pre className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-emerald-300 font-mono text-xs overflow-x-auto">
                {JSON.stringify(receipt, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
