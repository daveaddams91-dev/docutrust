import React, { useState } from 'react';
import Navbar from './components/Navbar.jsx';
import HeroSection from './components/HeroSection.jsx';
import IssuerStudio from './components/IssuerStudio.jsx';
import CertificateDesigner from './components/CertificateDesigner.jsx';
import MultiSigStudio from './components/MultiSigStudio.jsx';
import LiveScanner from './components/LiveScanner.jsx';
import EnterpriseDashboard from './components/EnterpriseDashboard.jsx';
import VerificationPortal from './components/VerificationPortal.jsx';
import SelectiveDisclosureStudio from './components/SelectiveDisclosureStudio.jsx';
import ProtocolSimulator from './components/ProtocolSimulator.jsx';
import DeveloperHub from './components/DeveloperHub.jsx';
import ArchitectureDocs from './components/ArchitectureDocs.jsx';
import FortressArmorStudio from './components/FortressArmorStudio.jsx';
import TrustRecoveryStudio from './components/TrustRecoveryStudio.jsx';
import BBSOracleStudio from './components/BBSOracleStudio.jsx';
import FederationDIDCommStudio from './components/FederationDIDCommStudio.jsx';
import SovereignStudio from './components/SovereignStudio.jsx';
import MeshStudio from './components/MeshStudio.jsx';
import AnonCredsStudio from './components/AnonCredsStudio.jsx';
import DKGStudio from './components/DKGStudio.jsx';
import SmartContractStudio from './components/SmartContractStudio.jsx';
import AuditBundleStudio from './components/AuditBundleStudio.jsx';
import ConfidentialComputeStudio from './components/ConfidentialComputeStudio.jsx';
import JsonLdStudio from './components/JsonLdStudio.jsx';
import TrustChainStudio from './components/TrustChainStudio.jsx';
import QuantumArmorStudio from './components/QuantumArmorStudio.jsx';
import BadgeStudio from './components/BadgeStudio.jsx';
import PolicyStudio from './components/PolicyStudio.jsx';
import RingSigStudio from './components/RingSigStudio.jsx';
import KeyTransparencyStudio from './components/KeyTransparencyStudio.jsx';
import SLHDSAStudio from './components/SLHDSAStudio.jsx';
import WebAuthnStudio from './components/WebAuthnStudio.jsx';
import CrossChainBridgeStudio from './components/CrossChainBridgeStudio.jsx';
import ZKSnarkStudio from './components/ZKSnarkStudio.jsx';
import TrustScoreStudio from './components/TrustScoreStudio.jsx';
import VerifiableComputeStudio from './components/VerifiableComputeStudio.jsx';
import VanishCredStudio from './components/VanishCredStudio.jsx';
import UniversalVerifierStudio from './components/UniversalVerifierStudio.jsx';
import ZKRecursiveStudio from './components/ZKRecursiveStudio.jsx';
import RevocationLatticeStudio from './components/RevocationLatticeStudio.jsx';
import AgentProvenanceStudio from './components/AgentProvenanceStudio.jsx';
import VRFOracleStudio from './components/VRFOracleStudio.jsx';
import ZKDSLStudio from './components/ZKDSLStudio.jsx';
import AIBOMStudio from './components/AIBOMStudio.jsx';
import PQRatchetStudio from './components/PQRatchetStudio.jsx';
import PolynomialCommitmentStudio from './components/PolynomialCommitmentStudio.jsx';
import TEEAttestationStudio from './components/TEEAttestationStudio.jsx';
import IBCRelayerStudio from './components/IBCRelayerStudio.jsx';
import Footer from './components/Footer.jsx';

export default function App() {
  const [activeTab, setActiveTab] = useState('hero');
  const [selectedCredentialForVerify, setSelectedCredentialForVerify] = useState(null);

  const handleInspectCredential = (credential) => {
    setSelectedCredentialForVerify(credential);
    setActiveTab('verify');
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex flex-col font-sans selection:bg-blue-600 selection:text-white">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />

      <main className="flex-1">
        {activeTab === 'hero' && <HeroSection setActiveTab={setActiveTab} />}
        {activeTab === 'pq-ratchet' && <PQRatchetStudio />}
        {activeTab === 'poly-commit' && <PolynomialCommitmentStudio />}
        {activeTab === 'tee-attest' && <TEEAttestationStudio />}
        {activeTab === 'ibc-relayer' && <IBCRelayerStudio />}
        {activeTab === 'vrf-oracle' && <VRFOracleStudio />}
        {activeTab === 'zk-dsl' && <ZKDSLStudio />}
        {activeTab === 'ai-bom' && <AIBOMStudio />}
        {activeTab === 'zk-recursive' && <ZKRecursiveStudio />}
        {activeTab === 'lattice' && <RevocationLatticeStudio />}
        {activeTab === 'agent-provenance' && <AgentProvenanceStudio />}
        {activeTab === 'trustscore' && <TrustScoreStudio />}
        {activeTab === 'compute' && <VerifiableComputeStudio />}
        {activeTab === 'vanish' && <VanishCredStudio />}
        {activeTab === 'universal' && <UniversalVerifierStudio />}
        {activeTab === 'slhdsa' && <SLHDSAStudio />}
        {activeTab === 'webauthn' && <WebAuthnStudio />}
        {activeTab === 'crosschain' && <CrossChainBridgeStudio />}
        {activeTab === 'groth16' && <ZKSnarkStudio />}
        {activeTab === 'ringsig' && <RingSigStudio />}
        {activeTab === 'smt' && <KeyTransparencyStudio />}
        {activeTab === 'policy' && <PolicyStudio />}
        {activeTab === 'badge' && <BadgeStudio />}
        {activeTab === 'confidential' && <ConfidentialComputeStudio />}
        {activeTab === 'jsonld' && <JsonLdStudio />}
        {activeTab === 'trustchain' && <TrustChainStudio />}
        {activeTab === 'quantum-armor' && <QuantumArmorStudio />}
        {activeTab === 'anoncreds' && <AnonCredsStudio />}
        {activeTab === 'dkg' && <DKGStudio />}
        {activeTab === 'solidity' && <SmartContractStudio />}
        {activeTab === 'bundle' && <AuditBundleStudio />}
        {activeTab === 'mesh' && <MeshStudio />}
        {activeTab === 'sovereign' && <SovereignStudio />}
        {activeTab === 'armor' && <FortressArmorStudio />}
        {activeTab === 'trustmesh' && <TrustRecoveryStudio />}
        {activeTab === 'bbs' && <BBSOracleStudio />}
        {activeTab === 'didcomm' && <FederationDIDCommStudio />}
        {activeTab === 'issuer' && <IssuerStudio onInspectCredential={handleInspectCredential} />}
        {activeTab === 'designer' && <CertificateDesigner />}
        {activeTab === 'multisig' && <MultiSigStudio />}
        {activeTab === 'scanner' && <LiveScanner onVerificationSuccess={handleInspectCredential} />}
        {activeTab === 'dashboard' && <EnterpriseDashboard />}
        {activeTab === 'verify' && <VerificationPortal initialCredential={selectedCredentialForVerify} />}
        {activeTab === 'privacy' && <SelectiveDisclosureStudio />}
        {activeTab === 'simulator' && <ProtocolSimulator />}
        {activeTab === 'developers' && <DeveloperHub />}
        {activeTab === 'architecture' && <ArchitectureDocs />}
      </main>

      <Footer setActiveTab={setActiveTab} />
    </div>
  );
}

