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
