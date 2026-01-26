import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { ShieldCheck, Activity, AlertTriangle, Cpu } from 'lucide-react';

const data = [
    { name: '00:00', cpu: 10, mem: 20 },
    { name: '04:00', cpu: 15, mem: 22 },
    { name: '08:00', cpu: 35, mem: 40 },
    { name: '12:00', cpu: 25, mem: 35 },
    { name: '16:00', cpu: 45, mem: 45 },
    { name: '20:00', cpu: 20, mem: 30 },
    { name: '24:00', cpu: 15, mem: 25 },
];

const StatCard = ({ title, value, icon: Icon, trend, color }) => (
    <div className="bg-dark-800 border border-dark-700 rounded-xl p-6 relative overflow-hidden group hover:border-dark-600 transition-all">
        <div className={`absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity text-${color}-500`}>
            <Icon className="w-24 h-24 transform translate-x-4 -translate-y-4" />
        </div>
        <div className="relative z-10">
            <div className="flex justify-between items-start mb-4">
                <div className={`p-2 rounded-lg bg-${color}-500/10 text-${color}-500`}>
                    <Icon className="w-6 h-6" />
                </div>
                <span className={`text-sm font-bold ${trend > 0 ? 'text-red-400' : 'text-green-400'}`}>
                    {trend > 0 ? '+' : ''}{trend}%
                </span>
            </div>
            <h3 className="text-gray-400 text-sm font-medium">{title}</h3>
            <p className="text-3xl font-bold mt-1">{value}</p>
        </div>
    </div>
);

const Dashboard = () => {
    return (
        <div className="space-y-6">
            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatCard title="Threat Level" value="Low" icon={ShieldCheck} color="green" trend={-5} />
                <StatCard title="Active Services" value="12/12" icon={Activity} color="blue" trend={0} />
                <StatCard title="Security Alerts" value="3" icon={AlertTriangle} color="yellow" trend={12} />
                <StatCard title="System Load" value="24%" icon={Cpu} color="purple" trend={-2} />
            </div>

            {/* Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 bg-dark-800 border border-dark-700 rounded-xl p-6">
                    <h3 className="text-lg font-bold mb-6">System Resource Usage</h3>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={data}>
                                <defs>
                                    <linearGradient id="colorCpu" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
                                <XAxis dataKey="name" stroke="#666" axisLine={false} tickLine={false} />
                                <YAxis stroke="#666" axisLine={false} tickLine={false} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#171717', borderColor: '#333' }}
                                    itemStyle={{ color: '#fff' }}
                                />
                                <Area type="monotone" dataKey="cpu" stroke="#8b5cf6" fillOpacity={1} fill="url(#colorCpu)" />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
                    <h3 className="text-lg font-bold mb-4">Recent Activity</h3>
                    <div className="space-y-4">
                        {[1, 2, 3, 4, 5].map((i) => (
                            <div key={i} className="flex items-start gap-3 p-3 rounded-lg hover:bg-dark-700/50 transition-colors">
                                <div className="w-2 h-2 mt-2 rounded-full bg-blue-500" />
                                <div>
                                    <p className="text-sm font-medium">Process started: nginx</p>
                                    <p className="text-xs text-gray-500">2 minutes ago</p>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
