import React, { useState, useEffect } from 'react';
import { ChartBarIcon, ArrowTrendingUpIcon, ArrowTrendingDownIcon, ClockIcon } from '@heroicons/react/24/outline';
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';

const Analytics = () => {
  const [timeRange, setTimeRange] = useState('7d');
  const [loading, setLoading] = useState(false);

  // Mock data for charts
  const operationsData = [
    { date: '2024-01-09', operations: 45, threats: 2 },
    { date: '2024-01-10', operations: 52, threats: 1 },
    { date: '2024-01-11', operations: 48, threats: 3 },
    { date: '2024-01-12', operations: 61, threats: 1 },
    { date: '2024-01-13', operations: 55, threats: 4 },
    { date: '2024-01-14', operations: 67, threats: 2 },
    { date: '2024-01-15', operations: 59, threats: 1 },
  ];

  const algorithmData = [
    { name: 'Kyber', value: 35, color: '#6366f1' },
    { name: 'Dilithium', value: 25, color: '#8b5cf6' },
    { name: 'AES', value: 20, color: '#06b6d4' },
    { name: 'RSA', value: 15, color: '#10b981' },
    { name: 'Hybrid', value: 5, color: '#f59e0b' },
  ];

  const performanceData = [
    { time: '00:00', response_time: 0.12, cpu_usage: 15 },
    { time: '04:00', response_time: 0.10, cpu_usage: 12 },
    { time: '08:00', response_time: 0.15, cpu_usage: 25 },
    { time: '12:00', response_time: 0.18, cpu_usage: 35 },
    { time: '16:00', response_time: 0.22, cpu_usage: 45 },
    { time: '20:00', response_time: 0.16, cpu_usage: 30 },
  ];

  const threatTypes = [
    { type: 'Quantum Attack', count: 5, trend: 'up' },
    { type: 'Brute Force', count: 23, trend: 'down' },
    { type: 'Anomalous Pattern', count: 12, trend: 'up' },
    { type: 'Injection Attack', count: 8, trend: 'down' },
  ];

  const MetricCard = ({ title, value, change, trend, icon: Icon }) => (
    <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{title}</p>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">{value}</p>
          {change && (
            <div className="flex items-center mt-1">
              {trend === 'up' ? (
                <ArrowTrendingUpIcon className="h-4 w-4 text-green-500" />
              ) : (
                <ArrowTrendingDownIcon className="h-4 w-4 text-red-500" />
              )}
              <span className={`text-sm font-medium ml-1 ${trend === 'up' ? 'text-green-600' : 'text-red-600'}`}>
                {change}
              </span>
            </div>
          )}
        </div>
        <div className="flex-shrink-0">
          <Icon className="h-8 w-8 text-gray-400" />
        </div>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-gray-200 dark:border-gray-700 pb-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Analytics</h1>
            <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
              Security metrics and performance insights
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
            >
              <option value="1d">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
              <option value="90d">Last 90 days</option>
            </select>
          </div>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Operations"
          value="2,847"
          change="+12.5%"
          trend="up"
          icon={ChartBarIcon}
        />
        <MetricCard
          title="Threats Detected"
          value="23"
          change="-8.3%"
          trend="down"
          icon={ChartBarIcon}
        />
        <MetricCard
          title="Avg Response Time"
          value="0.16s"
          change="+2.1%"
          trend="up"
          icon={ClockIcon}
        />
        <MetricCard
          title="Success Rate"
          value="99.2%"
          change="+0.5%"
          trend="up"
          icon={ArrowTrendingUpIcon}
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Operations Over Time */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            Operations & Threats Over Time
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={operationsData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="operations" stroke="#6366f1" strokeWidth={2} />
              <Line type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Algorithm Usage */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            Algorithm Usage Distribution
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={algorithmData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {algorithmData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Performance Metrics */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            Performance Metrics
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={performanceData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Area type="monotone" dataKey="response_time" stackId="1" stroke="#8884d8" fill="#8884d8" />
              <Area type="monotone" dataKey="cpu_usage" stackId="2" stroke="#82ca9d" fill="#82ca9d" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Threat Analysis */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            Threat Analysis
          </h3>
          <div className="space-y-4">
            {threatTypes.map((threat) => (
              <div key={threat.type} className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="flex-shrink-0">
                    {threat.trend === 'up' ? (
                      <ArrowTrendingUpIcon className="h-5 w-5 text-red-500" />
                    ) : (
                      <ArrowTrendingDownIcon className="h-5 w-5 text-green-500" />
                    )}
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white">
                      {threat.type}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {threat.trend === 'up' ? 'Increasing' : 'Decreasing'} trend
                    </p>
                  </div>
                </div>
                <div className="text-sm font-medium text-gray-900 dark:text-white">
                  {threat.count}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Detailed Analytics */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
          Detailed Security Analytics
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="space-y-4">
            <h4 className="text-md font-medium text-gray-900 dark:text-white">
              Quantum Protection
            </h4>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">Quantum-Safe Operations</span>
                <span className="text-sm font-medium text-gray-900 dark:text-white">78%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">Classical Operations</span>
                <span className="text-sm font-medium text-gray-900 dark:text-white">22%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">Hybrid Encryption</span>
                <span className="text-sm font-medium text-gray-900 dark:text-white">45%</span>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <h4 className="text-md font-medium text-gray-900 dark:text-white">
              AI Detection
            </h4>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">Detection Accuracy</span>
                <span className="text-sm font-medium text-gray-900 dark:text-white">94.2%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">False Positives</span>
                <span className="text-sm font-medium text-gray-900 dark:text-white">2.1%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">Response Time</span>
                <span className="text-sm font-medium text-gray-900 dark:text-white">0.089s</span>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <h4 className="text-md font-medium text-gray-900 dark:text-white">
              System Health
            </h4>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">Uptime</span>
                <span className="text-sm font-medium text-green-600">99.9%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">Memory Usage</span>
                <span className="text-sm font-medium text-gray-900 dark:text-white">45.2%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">CPU Usage</span>
                <span className="text-sm font-medium text-gray-900 dark:text-white">23.8%</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Analytics;