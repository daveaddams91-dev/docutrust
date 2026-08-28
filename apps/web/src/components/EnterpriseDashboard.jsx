import React, { useState } from 'react';
import { 
  Building2, 
  ShieldCheck, 
  Activity, 
  TrendingUp, 
  Key, 
  Lock, 
  XCircle, 
  CheckCircle2, 
  AlertTriangle, 
  Search, 
  Filter, 
  Download, 
  Plus, 
  Trash2,
  Copy,
  Sparkles,
  Zap
} from 'lucide-react';

export default function EnterpriseDashboard() {
  const [activeTab, setActiveTab] = useState('registry'); // 'registry' | 'apikeys' | 'security'
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

  // Initial Sample Credentials
  const [credentials, setCredentials] = useState([
    {
      id: 'urn:uuid:7f3b89e1-c2a0-4912-87f2-83d210a45b9e',
      recipient: 'Alex Rivera',
      degree: 'Master of Science in Computer Science',
      issuedDate: '2026-06-15',
      status: 'valid',
      pqcSafe: true,
      verifications: 142
    },
    {
      id: 'urn:uuid:4a1b3c5d-7e9f-0a2b-4c6d-8e0f1a3b5c7d',
      recipient: 'Elena Rostova',
      degree: 'Doctor of Philosophy in Artificial Intelligence',
      issuedDate: '2026-05-20',
      status: 'valid',
      pqcSafe: true,
      verifications: 89
    },
    {
      id: 'urn:uuid:6c0d8e2f-4a1b-3c5d-7e9f-0a2b4c6d8e0f',
      recipient: 'Marcus Vance',
      degree: 'Master of Science in Data Science',
      issuedDate: '2026-04-10',
      status: 'revoked',
      pqcSafe: false,
      verifications: 24
    },
    {
      id: 'urn:uuid:1e3f7a5b-6c0d-8e2f-4a1b-3c5d7e9f0a2b',
      recipient: 'Sarah Jenkins',
      degree: 'Bachelor of Science in Computer Engineering',
      issuedDate: '2026-03-01',
      status: 'valid',
      pqcSafe: true,
      verifications: 310
    },
    {
      id: 'urn:uuid:9e1287f2-b1d3-0c5e-4a1b-3c5d7e9f0a2b',
      recipient: 'David Kim',
      degree: 'Ph.D. in Quantum Information Science',
      issuedDate: '2026-01-18',
      status: 'valid',
      pqcSafe: true,
      verifications: 512
    }
  ]);

  // API Keys
  const [apiKeys, setApiKeys] = useState([
    { id: 'key_live_mit_01', name: 'MIT Canvas LMS Integration', key: 'dt_live_sec_994a82b1c8f2...', rate: '2,000 req/min', created: '2026-01-10', active: true },
    { id: 'key_live_mit_02', name: 'Workday HR Background Check API', key: 'dt_live_sec_117c93e4d5a8...', rate: '5,000 req/min', created: '2026-03-15', active: true }
  ]);
  const [newKeyName, setNewKeyName] = useState('');

  const toggleRevocation = (id) => {
    setCredentials(prev => prev.map(c => {
      if (c.id === id) {
        return { ...c, status: c.status === 'valid' ? 'revoked' : 'valid' };
      }
      return c;
    }));
  };

  const handleCreateApiKey = () => {
    if (!newKeyName) return;
    const chars = '0123456789abcdef';
    let hex = '';
    for (let i = 0; i < 24; i++) hex += chars[Math.floor(Math.random() * chars.length)];
    const newKey = {
      id: `key_live_${Date.now().toString().slice(-4)}`,
      name: newKeyName,
      key: `dt_live_sec_${hex.slice(0, 16)}...`,
      rate: '1,000 req/min',
      created: new Date().toISOString().split('T')[0],
      active: true
    };
    setApiKeys([...apiKeys, newKey]);
    setNewKeyName('');
  };

  const filteredCredentials = credentials.filter(c => {
    const matchesSearch = c.recipient.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          c.degree.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          c.id.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === 'all' || c.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 text-left space-y-10">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-indigo-400 mb-2 uppercase tracking-widest">
            <Building2 className="w-3.5 h-3.5" />
            <span>Institutional Governance Suite</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            Enterprise Management & Telemetry
          </h2>
          <p className="text-sm text-gray-400 mt-2">
            Monitor real-time credential lifecycle metrics, StatusList2021 revocations, API key scopes, and post-quantum readiness.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-2 bg-gray-900/80 p-1.5 rounded-xl border border-gray-800">
          <button
            onClick={() => setActiveTab('registry')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'registry' ? 'bg-indigo-600 text-white shadow-sm' : 'text-gray-400 hover:text-white'
            }`}
          >
            Credential Registry
          </button>
          <button
            onClick={() => setActiveTab('apikeys')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'apikeys' ? 'bg-indigo-600 text-white shadow-sm' : 'text-gray-400 hover:text-white'
            }`}
          >
            API Access Keys
          </button>
          <button
            onClick={() => setActiveTab('security')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'security' ? 'bg-indigo-600 text-white shadow-sm' : 'text-gray-400 hover:text-white'
            }`}
          >
            PQC Security Scorecard
          </button>
        </div>
      </div>

      {/* KPI Metrics Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className="glass-card p-5 rounded-2xl border border-gray-800 space-y-2">
          <div className="flex items-center justify-between text-gray-400 text-xs font-mono">
            <span>TOTAL ISSUED</span>
            <ShieldCheck className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-bold text-white">14,892</div>
          <div className="text-[11px] text-emerald-400 flex items-center gap-1 font-mono">
            <TrendingUp className="w-3 h-3" /> +18.4% this academic semester
          </div>
        </div>

        <div className="glass-card p-5 rounded-2xl border border-gray-800 space-y-2">
          <div className="flex items-center justify-between text-gray-400 text-xs font-mono">
            <span>VERIFICATIONS TODAY</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-bold text-white">1,420</div>
          <div className="text-[11px] text-gray-400 font-mono">Average latency: 0.038 ms</div>
        </div>

        <div className="glass-card p-5 rounded-2xl border border-gray-800 space-y-2">
          <div className="flex items-center justify-between text-gray-400 text-xs font-mono">
            <span>GAS FEES SAVED (MERKLE)</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-bold text-amber-400">$48,200</div>
          <div className="text-[11px] text-gray-400 font-mono">99.8% compression vs linear txs</div>
        </div>

        <div className="glass-card p-5 rounded-2xl border border-gray-800 space-y-2">
          <div className="flex items-center justify-between text-gray-400 text-xs font-mono">
            <span>PQC QUANTUM READINESS</span>
            <Sparkles className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-bold text-indigo-300">98.4%</div>
          <div className="text-[11px] text-indigo-400 font-mono">NIST FIPS 204 ML-DSA Hybrid</div>
        </div>
      </div>

      {/* TAB 1: CREDENTIAL REGISTRY */}
      {activeTab === 'registry' && (
        <div className="glass-card p-6 sm:p-8 rounded-2xl border border-gray-800 space-y-6">
          {/* Filters & Search */}
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500" />
              <input
                type="text"
                placeholder="Search by student name, degree, or ID..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-gray-950 border border-gray-800 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="flex items-center gap-2">
              {['all', 'valid', 'revoked'].map(st => (
                <button
                  key={st}
                  onClick={() => setStatusFilter(st)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono uppercase transition-all ${
                    statusFilter === st
                      ? 'bg-indigo-600 text-white font-bold'
                      : 'bg-gray-900 border border-gray-800 text-gray-400 hover:text-white'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-950">
            <table className="w-full text-left text-xs font-sans">
              <thead className="border-b border-gray-800 text-gray-400 font-mono text-[11px] uppercase bg-gray-900/60">
                <tr>
                  <th className="py-3 px-4">Recipient</th>
                  <th className="py-3 px-4">Degree / Qualification</th>
                  <th className="py-3 px-4">Issued Date</th>
                  <th className="py-3 px-4">Verifications</th>
                  <th className="py-3 px-4">PQC Safe</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60">
                {filteredCredentials.map(row => (
                  <tr key={row.id} className="hover:bg-gray-900/40 transition-colors">
                    <td className="py-3.5 px-4 font-semibold text-white">{row.recipient}</td>
                    <td className="py-3.5 px-4 text-gray-300">{row.degree}</td>
                    <td className="py-3.5 px-4 font-mono text-gray-400">{row.issuedDate}</td>
                    <td className="py-3.5 px-4 font-mono text-emerald-400">{row.verifications} checks</td>
                    <td className="py-3.5 px-4 font-mono">
                      {row.pqcSafe ? (
                        <span className="px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 text-[10px]">
                          ML-DSA Hybrid
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-gray-900 text-gray-500 text-[10px]">
                          Classical Ed25519
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`px-2.5 py-1 rounded-full text-[10px] font-mono font-bold inline-flex items-center gap-1 ${
                        row.status === 'valid'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                          : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                      }`}>
                        {row.status === 'valid' ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                        {row.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={() => toggleRevocation(row.id)}
                        className={`px-3 py-1 rounded-lg text-xs font-mono transition-colors ${
                          row.status === 'valid'
                            ? 'bg-rose-950/40 text-rose-300 hover:bg-rose-900/60 border border-rose-800/60'
                            : 'bg-emerald-950/40 text-emerald-300 hover:bg-emerald-900/60 border border-emerald-800/60'
                        }`}
                      >
                        {row.status === 'valid' ? 'Revoke Status' : 'Restore Valid'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: API KEYS */}
      {activeTab === 'apikeys' && (
        <div className="glass-card p-6 sm:p-8 rounded-2xl border border-gray-800 space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h3 className="text-lg font-bold text-white">Multi-Tenant Organization API Keys</h3>
              <p className="text-xs text-gray-400 mt-1">
                Provide secure programmatic access to third-party LMS (Canvas, Blackboard) and HR recruitment software.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder="New integration name (e.g. Workday HR)"
                value={newKeyName}
                onChange={e => setNewKeyName(e.target.value)}
                className="px-3.5 py-2 rounded-xl bg-gray-950 border border-gray-800 text-xs text-white focus:outline-none focus:border-indigo-500 w-64"
              />
              <button
                onClick={handleCreateApiKey}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-md shadow-indigo-600/30 transition-all"
              >
                <Plus className="w-3.5 h-3.5" />
                Generate Key
              </button>
            </div>
          </div>

          <div className="space-y-3">
            {apiKeys.map(k => (
              <div key={k.id} className="p-4 rounded-xl bg-gray-950 border border-gray-800 flex flex-wrap items-center justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-white">{k.name}</span>
                    <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-[10px] font-mono">Active</span>
                  </div>
                  <div className="text-xs font-mono text-gray-400">{k.key}</div>
                </div>

                <div className="flex items-center gap-4 text-xs font-mono text-gray-400">
                  <span>Rate: {k.rate}</span>
                  <span>Created: {k.created}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 3: PQC SECURITY SCORECARD */}
      {activeTab === 'security' && (
        <div className="glass-card p-6 sm:p-8 rounded-2xl border border-gray-800 space-y-6">
          <div>
            <h3 className="text-lg font-bold text-white">Post-Quantum Cryptography (PQC) Security Scorecard</h3>
            <p className="text-xs text-gray-400 mt-1">
              Assessment of institutional credential resilience against Shor's and Grover's quantum factorization algorithms.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="p-5 rounded-xl bg-gray-950 border border-indigo-500/30 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white">NIST FIPS 204 Lattice Readiness</span>
                <span className="text-indigo-400 font-mono font-bold">100%</span>
              </div>
              <p className="text-xs text-gray-400">
                All newly issued credentials default to hybrid ML-DSA-65 with Ed25519 fallback.
              </p>
            </div>

            <div className="p-5 rounded-xl bg-gray-950 border border-gray-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white">50-Year Diploma Longevity</span>
                <span className="text-emerald-400 font-mono font-bold">Guaranteed</span>
              </div>
              <p className="text-xs text-gray-400">
                Mathematical proofs remain unforgeable even after commercial quantum computer emergence.
              </p>
            </div>

            <div className="p-5 rounded-xl bg-gray-950 border border-gray-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white">RFC 8785 JCS Hashing Sponge</span>
                <span className="text-cyan-400 font-mono font-bold">SHAKE-256</span>
              </div>
              <p className="text-xs text-gray-400">
                Quantum-resistant sponge hash function for deterministic claim tree blinding.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
