import React, { useEffect, useState } from 'react';
import { dashboardAPI } from '../services/api';
import { 
  ShieldCheckIcon, 
  ExclamationTriangleIcon, 
  CpuChipIcon, 
  ChartBarIcon,
  BugAntIcon,
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon
} from '@heroicons/react/24/outline';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from 'recharts';

const Dashboard = () => {
  const [overview, setOverview] = useState(null);
  const [securityStatus, setSecurityStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setLoading(true);
        const [overviewRes, securityRes] = await Promise.all([
          dashboardAPI.getOverview(),
          dashboardAPI.getSecurityStatus()
        ]);
        
        setOverview(overviewRes.data);
        setSecurityStatus(securityRes.data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();
  }, []);

  const StatCard = ({ title, value, icon: Icon, trend, color = 'indigo' }) => (
    <div className="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
      <div className="p-5">
        <div className="flex items-center">
          <div className="flex-shrink-0">
            <Icon className={`h-6 w-6 text-${color}-600`} />
          </div>
          <div className="ml-5 w-0 flex-1">
            <dl>
              <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                {title}
              </dt>
              <dd className="text-lg font-medium text-gray-900 dark:text-white">
                {value}
              </dd>
            </dl>
          </div>
        </div>
      </div>
      {trend && (
        <div className="bg-gray-50 dark:bg-gray-700 px-5 py-3">
          <div className="text-sm">
            <span className={`font-medium ${trend > 0 ? 'text-green-600' : 'text-red-600'}`}>
              {trend > 0 ? '+' : ''}{trend}%
            </span>
            <span className="text-gray-500 dark:text-gray-400"> from last month</span>
          </div>
        </div>
      )}
    </div>
  );

  const ThreatChart = ({ data }) => (
    <ResponsiveContainer width="100%" height={200}>
      <LineChart data={data}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="time" />
        <YAxis />
        <Tooltip />
        <Line type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2} />
      </LineChart>
    </ResponsiveContainer>
  );

  const AlgorithmUsageChart = ({ data }) => {
    const COLORS = ['#6366f1', '#8b5cf6', '#06b6d4', '#10b981', '#f59e0b'];
    
    return (
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            labelLine={false}
            label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
            outerRadius={80}
            fill="#8884d8"
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip />
        </PieChart>
      </ResponsiveContainer>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-md bg-red-50 dark:bg-red-900 p-4">
        <div className="flex">
          <XCircleIcon className="h-5 w-5 text-red-400" />
          <div className="ml-3">
            <h3 className="text-sm font-medium text-red-800 dark:text-red-200">
              Error loading dashboard
            </h3>
            <p className="mt-2 text-sm text-red-700 dark:text-red-300">{error}</p>
          </div>
        </div>
      </div>
    );
  }

  // Mock data for charts
  const threatData = [
    { time: '00:00', threats: 2 },
    { time: '04:00', threats: 1 },
    { time: '08:00', threats: 5 },
    { time: '12:00', threats: 3 },
    { time: '16:00', threats: 7 },
    { time: '20:00', threats: 4 },
  ];

  const algorithmData = [
    { name: 'Kyber', value: 35 },
    { name: 'Dilithium', value: 25 },
    { name: 'AES', value: 20 },
    { name: 'RSA', value: 15 },
    { name: 'Hybrid', value: 5 },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="border-b border-gray-200 dark:border-gray-700 pb-4">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
        <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
          Overview of your QuantumGate security posture
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Operations"
          value={overview?.encryption_stats?.total_operations || 0}
          icon={CpuChipIcon}
          trend={12}
          color="indigo"
        />
        <StatCard
          title="Threats Detected"
          value={overview?.threat_stats?.total_threats || 0}
          icon={ExclamationTriangleIcon}
          trend={-5}
          color="red"
        />
        <StatCard
          title="Quantum Resistant"
          value={`${overview?.encryption_stats?.quantum_resistant_ops || 0}%`}
          icon={ShieldCheckIcon}
          trend={8}
          color="green"
        />
        <StatCard
          title="Bug Reports"
          value={overview?.bug_bounty_stats?.total_reports || 0}
          icon={BugAntIcon}
          trend={3}
          color="yellow"
        />
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Detection Chart */}
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            Threat Detection (24h)
          </h3>
          <ThreatChart data={threatData} />
        </div>

        {/* Algorithm Usage Chart */}
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            Algorithm Usage
          </h3>
          <AlgorithmUsageChart data={algorithmData} />
        </div>
      </div>

      {/* Security Status */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            Security Status
          </h3>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <div className="flex items-center">
              <CheckCircleIcon className="h-5 w-5 text-green-500 mr-2" />
              <span className="text-sm text-gray-700 dark:text-gray-300">
                Quantum Protection Active
              </span>
            </div>
            <div className="flex items-center">
              <CheckCircleIcon className="h-5 w-5 text-green-500 mr-2" />
              <span className="text-sm text-gray-700 dark:text-gray-300">
                Threat Detection Online
              </span>
            </div>
            <div className="flex items-center">
              <CheckCircleIcon className="h-5 w-5 text-green-500 mr-2" />
              <span className="text-sm text-gray-700 dark:text-gray-300">
                Blockchain Integration Ready
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            Recent Activity
          </h3>
          <div className="flow-root">
            <ul className="-mb-8">
              {overview?.recent_activities?.map((activity, index) => (
                <li key={index}>
                  <div className="relative pb-8">
                    {index !== overview.recent_activities.length - 1 && (
                      <span className="absolute top-4 left-4 -ml-px h-full w-0.5 bg-gray-200 dark:bg-gray-600" />
                    )}
                    <div className="relative flex space-x-3">
                      <div>
                        <span className="h-8 w-8 rounded-full bg-indigo-500 flex items-center justify-center ring-8 ring-white dark:ring-gray-800">
                          <ClockIcon className="h-5 w-5 text-white" />
                        </span>
                      </div>
                      <div className="min-w-0 flex-1 pt-1.5 flex justify-between space-x-4">
                        <div>
                          <p className="text-sm text-gray-500 dark:text-gray-400">
                            {activity.description}
                          </p>
                        </div>
                        <div className="text-right text-sm whitespace-nowrap text-gray-500 dark:text-gray-400">
                          {activity.timestamp}
                        </div>
                      </div>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {/* AI Recommendations */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            AI Recommendations
          </h3>
          <div className="space-y-3">
            {overview?.ai_recommendations?.map((recommendation, index) => (
              <div key={index} className="flex items-start space-x-3">
                <div className={`flex-shrink-0 w-2 h-2 rounded-full mt-2 ${
                  recommendation.priority === 'high' ? 'bg-red-500' :
                  recommendation.priority === 'medium' ? 'bg-yellow-500' :
                  'bg-green-500'
                }`} />
                <div>
                  <p className="text-sm text-gray-700 dark:text-gray-300">
                    {recommendation.message}
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    {recommendation.type}
                  </p>
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