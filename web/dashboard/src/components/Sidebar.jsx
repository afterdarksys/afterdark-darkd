import React from 'react';
import { LayoutDashboard, FileText, Scan, Terminal, Settings, ShieldAlert } from 'lucide-react';

const Sidebar = ({ activeTab, setActiveTab }) => {
    const navItems = [
        { id: 'dashboard', icon: LayoutDashboard, label: 'Dashboard' },
        { id: 'logs', icon: FileText, label: 'Logs & Events' },
        { id: 'scans', icon: Scan, label: 'Scan Manager' },
        { id: 'policies', icon: ShieldAlert, label: 'Policies' },
        { id: 'console', icon: Terminal, label: 'Debug Console' },
        { id: 'settings', icon: Settings, label: 'Settings' },
    ];

    return (
        <aside className="w-64 bg-dark-800 border-r border-dark-700 flex flex-col">
            <div className="p-6 border-b border-dark-700/50">
                <div className="flex items-center gap-3">
                    <div className="w-8 h-8 bg-brand-500 rounded-lg flex items-center justify-center shadow-lg shadow-brand-500/20">
                        <ShieldAlert className="w-5 h-5 text-white" />
                    </div>
                    <span className="font-bold text-lg tracking-tight">AfterDark</span>
                </div>
            </div>

            <nav className="flex-1 p-4 space-y-2">
                {navItems.map((item) => (
                    <button
                        key={item.id}
                        onClick={() => setActiveTab(item.id)}
                        className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 group ${activeTab === item.id
                                ? 'bg-brand-500/10 text-brand-500 border border-brand-500/20'
                                : 'text-gray-400 hover:bg-dark-700 hover:text-gray-100'
                            }`}
                    >
                        <item.icon className="w-5 h-5" />
                        <span className="font-medium">{item.label}</span>
                    </button>
                ))}
            </nav>

            <div className="p-4 border-t border-dark-700/50">
                <div className="bg-dark-900/50 rounded-lg p-3 border border-dark-700">
                    <p className="text-xs text-gray-500 uppercase font-bold mb-2">System Status</p>
                    <div className="space-y-2">
                        <div className="flex justify-between text-xs">
                            <span className="text-gray-400">Daemon</span>
                            <span className="text-green-400">Running</span>
                        </div>
                        <div className="flex justify-between text-xs">
                            <span className="text-gray-400">Version</span>
                            <span className="text-gray-300">alpha-0.5</span>
                        </div>
                    </div>
                </div>
            </div>
        </aside>
    );
};

export default Sidebar;
