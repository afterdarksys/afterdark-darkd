import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import { Shield, Activity, Terminal, Settings } from 'lucide-react';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');

  return (
    <div className="flex h-screen bg-dark-900 text-gray-100 font-sans overflow-hidden">
      {/* Sidebar */}
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto bg-dark-900/50 backdrop-blur-sm p-8">
        <header className="mb-8 flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold bg-gradient-to-r from-brand-500 to-purple-500 bg-clip-text text-transparent">
              AfterDark Security
            </h1>
            <p className="text-gray-400 mt-1">System Protection Daemon</p>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 px-3 py-1 bg-green-500/10 text-green-400 rounded-full border border-green-500/20">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
              <span className="text-sm font-medium">Protected</span>
            </div>
            <div className="w-10 h-10 rounded-full bg-dark-700 border border-dark-600 flex items-center justify-center">
              <span className="text-sm font-bold">AD</span>
            </div>
          </div>
        </header>

        {activeTab === 'dashboard' && <Dashboard />}
        {activeTab !== 'dashboard' && (
          <div className="flex items-center justify-center h-64 border border-dashed border-dark-700 rounded-lg">
            <p className="text-gray-500">Module {activeTab} is initializing...</p>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
