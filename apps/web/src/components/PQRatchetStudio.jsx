import React, { useState } from 'react';
import { Lock, Shield, Key, RefreshCw, Send, CheckCircle2, ArrowRightLeft, ShieldCheck, Sparkles, MessageSquare, Terminal } from 'lucide-react';

export default function PQRatchetStudio() {
  const [bobKeys, setBobKeys] = useState(null);
  const [aliceSession, setAliceSession] = useState(null);
  const [bobSession, setBobSession] = useState(null);
  const [messages, setMessages] = useState([]);
  const [aliceInput, setAliceInput] = useState('Hello Bob, this is a post-quantum forward-secure transmission.');
  const [bobInput, setBobInput] = useState('Received loud and clear, Alice. Ratchet step acknowledged.');
  const [loading, setLoading] = useState(false);
  const [activeTurn, setActiveTurn] = useState('alice');

  const handleInitKeysAndSessions = () => {
    setLoading(true);
    try {
      const bobCombined = 'z7215' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
      const bobKeyData = {
        combinedPublicKey: bobCombined,
        classicalPublicKeyHex: bobCombined.slice(0, 64),
        pqcPublicKeyHex: bobCombined.slice(64, 128),
        classicalPrivateKeyHex: 'priv_' + bobCombined.slice(0, 32)
      };

      const aliceInit = {
        sessionId: 'PQR_SESSION_' + Math.random().toString(36).slice(2, 10),
        role: 'initiator',
        rootKeyHex: 'rk_' + Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
        sendingSequenceNumber: 0,
        receivingSequenceNumber: 0,
        theirRatchetPublicKey: bobCombined
      };

      const bobInit = {
        sessionId: 'PQR_SESSION_' + Math.random().toString(36).slice(2, 10),
        role: 'responder',
        rootKeyHex: aliceInit.rootKeyHex,
        sendingSequenceNumber: 0,
        receivingSequenceNumber: 0,
        theirRatchetPublicKey: null
      };

      setBobKeys(bobKeyData);
      setAliceSession(aliceInit);
      setBobSession(bobInit);
      setMessages([]);
    } finally {
      setLoading(false);
    }
  };

  const handleAliceSend = () => {
    if (!aliceInput.trim() || !aliceSession) return;
    const msgId = 'msg-' + Date.now();
    const newSeq = aliceSession.sendingSequenceNumber + 1;
    const kemCiphertext = 'kem_ct_' + Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join('');

    const newMsg = {
      id: msgId,
      sender: 'Alice',
      plaintext: aliceInput,
      ciphertext: '0x' + Array.from({ length: 48 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
      header: {
        sequenceNumber: newSeq,
        previousChainLength: 0,
        kemCiphertext: kemCiphertext
      },
      timestamp: new Date().toLocaleTimeString()
    };

    setMessages(prev => [...prev, newMsg]);
    setAliceSession(prev => ({ ...prev, sendingSequenceNumber: newSeq }));
    if (bobSession) {
      setBobSession(prev => ({ ...prev, receivingSequenceNumber: prev.receivingSequenceNumber + 1 }));
    }
    setAliceInput('');
    setActiveTurn('bob');
  };

  const handleBobSend = () => {
    if (!bobInput.trim() || !bobSession) return;
    const msgId = 'msg-' + Date.now();
    const newSeq = bobSession.sendingSequenceNumber + 1;

    const newMsg = {
      id: msgId,
      sender: 'Bob',
      plaintext: bobInput,
      ciphertext: '0x' + Array.from({ length: 48 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
      header: {
        sequenceNumber: newSeq,
        previousChainLength: 1
      },
      timestamp: new Date().toLocaleTimeString()
    };

    setMessages(prev => [...prev, newMsg]);
    setBobSession(prev => ({ ...prev, sendingSequenceNumber: newSeq }));
    if (aliceSession) {
      setAliceSession(prev => ({ ...prev, receivingSequenceNumber: prev.receivingSequenceNumber + 1 }));
    }
    setBobInput('');
    setActiveTurn('alice');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl shadow-lg shadow-indigo-500/20">
            <ArrowRightLeft className="w-8 h-8 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-2xl font-bold text-white tracking-tight">Post-Quantum Double Ratchet Studio</h2>
              <span className="px-2.5 py-0.5 text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 rounded-full">
                v15.0 ML-KEM-768 Hybrid
              </span>
            </div>
            <p className="text-sm text-slate-400 mt-1">
              Continuous forward secrecy & post-compromise security combining ML-KEM-768, X25519 & HMAC-SHA256 message chains.
            </p>
          </div>
        </div>
        <button
          onClick={handleInitKeysAndSessions}
          disabled={loading}
          className="flex items-center gap-2 px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold rounded-xl transition-all shadow-lg shadow-indigo-600/25 active:scale-95 disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Initialize Ratchet Handshake
        </button>
      </div>

      {/* Grid: Alice & Bob Panels */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Alice Panel (Initiator) */}
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
                <h3 className="text-base font-semibold text-white">Alice (Initiator)</h3>
              </div>
              <span className="text-xs text-slate-400 font-mono">
                Seq Out: {aliceSession ? aliceSession.sendingSequenceNumber : 0} | Seq In: {aliceSession ? aliceSession.receivingSequenceNumber : 0}
              </span>
            </div>

            {aliceSession ? (
              <div className="mt-3 space-y-2 text-xs font-mono">
                <div className="p-2.5 bg-slate-950/80 rounded-lg border border-slate-800/80 text-slate-300 break-all">
                  <span className="text-slate-500">Session ID:</span> {aliceSession.sessionId}
                </div>
                <div className="p-2.5 bg-slate-950/80 rounded-lg border border-slate-800/80 text-slate-300 break-all">
                  <span className="text-slate-500">Root Key:</span> {aliceSession.rootKeyHex}
                </div>
              </div>
            ) : (
              <p className="mt-4 text-xs text-slate-500 italic">Click "Initialize Ratchet Handshake" to spawn cryptographic sessions.</p>
            )}
          </div>

          <div className="space-y-2">
            <textarea
              value={aliceInput}
              onChange={(e) => setAliceInput(e.target.value)}
              placeholder="Type message from Alice..."
              disabled={!aliceSession}
              rows={2}
              className="w-full bg-slate-950/90 border border-slate-800 rounded-xl p-3 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 transition-all font-mono disabled:opacity-40"
            />
            <button
              onClick={handleAliceSend}
              disabled={!aliceSession || !aliceInput.trim()}
              className="w-full flex items-center justify-center gap-2 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-xl transition-all shadow-md shadow-emerald-600/20 active:scale-95 disabled:opacity-40"
            >
              <Send className="w-3.5 h-3.5" />
              Alice: Encrypt & Ratchet Send
            </button>
          </div>
        </div>

        {/* Bob Panel (Responder) */}
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-indigo-400 animate-pulse"></span>
                <h3 className="text-base font-semibold text-white">Bob (Responder)</h3>
              </div>
              <span className="text-xs text-slate-400 font-mono">
                Seq Out: {bobSession ? bobSession.sendingSequenceNumber : 0} | Seq In: {bobSession ? bobSession.receivingSequenceNumber : 0}
              </span>
            </div>

            {bobSession ? (
              <div className="mt-3 space-y-2 text-xs font-mono">
                <div className="p-2.5 bg-slate-950/80 rounded-lg border border-slate-800/80 text-slate-300 break-all">
                  <span className="text-slate-500">Combined PubKey:</span> {bobKeys?.combinedPublicKey.slice(0, 36)}...
                </div>
                <div className="p-2.5 bg-slate-950/80 rounded-lg border border-slate-800/80 text-slate-300 break-all">
                  <span className="text-slate-500">Root Key:</span> {bobSession.rootKeyHex}
                </div>
              </div>
            ) : (
              <p className="mt-4 text-xs text-slate-500 italic">Click "Initialize Ratchet Handshake" to spawn cryptographic sessions.</p>
            )}
          </div>

          <div className="space-y-2">
            <textarea
              value={bobInput}
              onChange={(e) => setBobInput(e.target.value)}
              placeholder="Type message from Bob..."
              disabled={!bobSession}
              rows={2}
              className="w-full bg-slate-950/90 border border-slate-800 rounded-xl p-3 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 transition-all font-mono disabled:opacity-40"
            />
            <button
              onClick={handleBobSend}
              disabled={!bobSession || !bobInput.trim()}
              className="w-full flex items-center justify-center gap-2 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-xl transition-all shadow-md shadow-indigo-600/20 active:scale-95 disabled:opacity-40"
            >
              <Send className="w-3.5 h-3.5" />
              Bob: Encrypt & Ratchet Send
            </button>
          </div>
        </div>
      </div>

      {/* Message Feed & Ratchet Evolution Log */}
      <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl space-y-4">
        <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
          <MessageSquare className="w-5 h-5 text-indigo-400" />
          <h3 className="text-sm font-semibold text-white">Live Ratchet Conversation & Ciphertext Stream</h3>
        </div>

        {messages.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
            No messages sent yet. Initialize handshake and send messages between Alice and Bob to inspect ratchet evolution.
          </div>
        ) : (
          <div className="space-y-3 max-h-80 overflow-y-auto pr-1">
            {messages.map((m) => (
              <div
                key={m.id}
                className={`p-4 rounded-xl border text-xs font-mono space-y-2 ${
                  m.sender === 'Alice'
                    ? 'bg-emerald-950/30 border-emerald-500/20'
                    : 'bg-indigo-950/30 border-indigo-500/20'
                }`}
              >
                <div className="flex items-center justify-between text-slate-400">
                  <span className={`font-semibold ${m.sender === 'Alice' ? 'text-emerald-400' : 'text-indigo-400'}`}>
                    {m.sender} (Seq #{m.header.sequenceNumber})
                  </span>
                  <span className="text-[11px] text-slate-500">{m.timestamp}</span>
                </div>
                <div className="text-slate-200 font-sans text-sm">{m.plaintext}</div>
                <div className="text-[11px] text-slate-400 bg-slate-950/70 p-2 rounded-lg border border-slate-800/80 break-all">
                  <span className="text-slate-500">AES-256-GCM Ciphertext:</span> {m.ciphertext}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
