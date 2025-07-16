import React, { useState, useEffect } from 'react';
import { BugAntIcon, TrophyIcon, CurrencyDollarIcon, UserGroupIcon } from '@heroicons/react/24/outline';

const BugBounty = () => {
  const [activeTab, setActiveTab] = useState('submit');
  const [loading, setLoading] = useState(false);
  const [reports, setReports] = useState([]);
  const [leaderboard, setLeaderboard] = useState([]);
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    severity: 'medium',
    category: 'general',
    steps_to_reproduce: '',
    proof_of_concept: '',
    affected_components: ''
  });

  useEffect(() => {
    // Mock data
    const mockReports = [
      {
        id: 'BR-001',
        title: 'SQL Injection in User Authentication',
        severity: 'high',
        category: 'general',
        status: 'under_review',
        reward: 3000,
        submitted_at: '2024-01-10T14:30:00Z'
      },
      {
        id: 'BR-002', 
        title: 'Kyber Key Generation Vulnerability',
        severity: 'critical',
        category: 'crypto',
        status: 'accepted',
        reward: 8000,
        submitted_at: '2024-01-08T09:15:00Z'
      }
    ];

    const mockLeaderboard = [
      { rank: 1, name: 'Alice Johnson', reports: 12, rewards: 25000 },
      { rank: 2, name: 'Bob Wilson', reports: 8, rewards: 18000 },
      { rank: 3, name: 'Charlie Brown', reports: 6, rewards: 15000 },
      { rank: 4, name: 'Diana Prince', reports: 10, rewards: 12000 },
      { rank: 5, name: 'Eve Adams', reports: 7, rewards: 9500 }
    ];

    setReports(mockReports);
    setLeaderboard(mockLeaderboard);
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    // Simulate submission
    setTimeout(() => {
      const newReport = {
        id: `BR-${String(reports.length + 1).padStart(3, '0')}`,
        title: formData.title,
        severity: formData.severity,
        category: formData.category,
        status: 'submitted',
        reward: 0,
        submitted_at: new Date().toISOString()
      };
      
      setReports([newReport, ...reports]);
      setFormData({
        title: '',
        description: '',
        severity: 'medium',
        category: 'general',
        steps_to_reproduce: '',
        proof_of_concept: '',
        affected_components: ''
      });
      setLoading(false);
    }, 2000);
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-800 bg-red-100';
      case 'high': return 'text-orange-800 bg-orange-100';
      case 'medium': return 'text-yellow-800 bg-yellow-100';
      case 'low': return 'text-green-800 bg-green-100';
      default: return 'text-gray-800 bg-gray-100';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'accepted': return 'text-green-800 bg-green-100';
      case 'under_review': return 'text-blue-800 bg-blue-100';
      case 'rejected': return 'text-red-800 bg-red-100';
      case 'fixed': return 'text-purple-800 bg-purple-100';
      case 'paid': return 'text-indigo-800 bg-indigo-100';
      default: return 'text-gray-800 bg-gray-100';
    }
  };

  const tabs = [
    { id: 'submit', name: 'Submit Report', icon: BugAntIcon },
    { id: 'reports', name: 'My Reports', icon: UserGroupIcon },
    { id: 'leaderboard', name: 'Leaderboard', icon: TrophyIcon },
    { id: 'guidelines', name: 'Guidelines', icon: CurrencyDollarIcon }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-gray-200 dark:border-gray-700 pb-4">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Bug Bounty Program</h1>
        <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
          Help us improve QuantumGate security and earn rewards
        </p>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <div className="flex items-center">
            <BugAntIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Total Reports</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">156</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <div className="flex items-center">
            <CurrencyDollarIcon className="h-8 w-8 text-green-500" />
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Total Rewards</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">$245,000</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <div className="flex items-center">
            <TrophyIcon className="h-8 w-8 text-yellow-500" />
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Top Researcher</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">Alice J.</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <div className="flex items-center">
            <UserGroupIcon className="h-8 w-8 text-purple-500" />
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Researchers</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">89</p>
            </div>
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`${
                activeTab === tab.id
                  ? 'border-indigo-500 text-indigo-600 dark:text-indigo-400'
                  : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
              } whitespace-nowrap py-2 px-1 border-b-2 font-medium text-sm flex items-center`}
            >
              <tab.icon className="h-5 w-5 mr-2" />
              {tab.name}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
        {activeTab === 'submit' && (
          <div className="p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
              Submit Bug Report
            </h3>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Title *
                </label>
                <input
                  type="text"
                  value={formData.title}
                  onChange={(e) => setFormData({...formData, title: e.target.value})}
                  required
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                  placeholder="Brief description of the vulnerability"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Severity *
                  </label>
                  <select
                    value={formData.severity}
                    onChange={(e) => setFormData({...formData, severity: e.target.value})}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                  >
                    <option value="low">Low ($100-$500)</option>
                    <option value="medium">Medium ($500-$2,000)</option>
                    <option value="high">High ($2,000-$5,000)</option>
                    <option value="critical">Critical ($5,000-$20,000)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Category *
                  </label>
                  <select
                    value={formData.category}
                    onChange={(e) => setFormData({...formData, category: e.target.value})}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                  >
                    <option value="general">General</option>
                    <option value="crypto">Cryptography</option>
                    <option value="ai">AI/ML</option>
                    <option value="blockchain">Blockchain</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Description *
                </label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({...formData, description: e.target.value})}
                  required
                  rows={4}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                  placeholder="Detailed description of the vulnerability"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Steps to Reproduce *
                </label>
                <textarea
                  value={formData.steps_to_reproduce}
                  onChange={(e) => setFormData({...formData, steps_to_reproduce: e.target.value})}
                  required
                  rows={4}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                  placeholder="Step-by-step instructions to reproduce the issue"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Proof of Concept
                </label>
                <textarea
                  value={formData.proof_of_concept}
                  onChange={(e) => setFormData({...formData, proof_of_concept: e.target.value})}
                  rows={4}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                  placeholder="Code, screenshots, or other proof of concept"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Affected Components
                </label>
                <input
                  type="text"
                  value={formData.affected_components}
                  onChange={(e) => setFormData({...formData, affected_components: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                  placeholder="List of affected components (comma-separated)"
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-4 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
              >
                {loading ? 'Submitting...' : 'Submit Report'}
              </button>
            </form>
          </div>
        )}

        {activeTab === 'reports' && (
          <div className="p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
              My Reports
            </h3>
            <div className="space-y-4">
              {reports.map((report) => (
                <div key={report.id} className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                        {report.title}
                      </h4>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(report.severity)}`}>
                        {report.severity}
                      </span>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(report.status)}`}>
                        {report.status}
                      </span>
                    </div>
                    <div className="text-sm text-gray-500 dark:text-gray-400">
                      {report.reward > 0 ? `$${report.reward.toLocaleString()}` : 'Pending'}
                    </div>
                  </div>
                  <div className="mt-2 flex items-center space-x-4 text-sm text-gray-500 dark:text-gray-400">
                    <span>ID: {report.id}</span>
                    <span>•</span>
                    <span>Category: {report.category}</span>
                    <span>•</span>
                    <span>Submitted: {new Date(report.submitted_at).toLocaleDateString()}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'leaderboard' && (
          <div className="p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
              Top Researchers
            </h3>
            <div className="space-y-4">
              {leaderboard.map((researcher) => (
                <div key={researcher.rank} className="flex items-center justify-between p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
                  <div className="flex items-center space-x-4">
                    <div className="flex items-center justify-center w-8 h-8 bg-indigo-100 dark:bg-indigo-900 rounded-full">
                      <span className="text-sm font-medium text-indigo-600 dark:text-indigo-300">
                        {researcher.rank}
                      </span>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-900 dark:text-white">
                        {researcher.name}
                      </p>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {researcher.reports} reports
                      </p>
                    </div>
                  </div>
                  <div className="text-sm font-medium text-gray-900 dark:text-white">
                    ${researcher.rewards.toLocaleString()}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'guidelines' && (
          <div className="p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
              Bug Bounty Guidelines
            </h3>
            <div className="space-y-6">
              <div>
                <h4 className="text-md font-medium text-gray-900 dark:text-white mb-2">
                  Reward Structure
                </h4>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Critical</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white">$5,000 - $20,000</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600 dark:text-gray-400">High</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white">$2,000 - $5,000</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Medium</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white">$500 - $2,000</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Low</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white">$100 - $500</span>
                  </div>
                </div>
              </div>

              <div>
                <h4 className="text-md font-medium text-gray-900 dark:text-white mb-2">
                  Categories
                </h4>
                <ul className="space-y-2 text-sm text-gray-600 dark:text-gray-400">
                  <li>• <strong>Cryptography:</strong> Post-quantum algorithm vulnerabilities (+50% bonus)</li>
                  <li>• <strong>AI/ML:</strong> Threat detection bypasses (+30% bonus)</li>
                  <li>• <strong>Blockchain:</strong> Smart contract vulnerabilities (+40% bonus)</li>
                  <li>• <strong>General:</strong> Web application security issues</li>
                </ul>
              </div>

              <div>
                <h4 className="text-md font-medium text-gray-900 dark:text-white mb-2">
                  Rules
                </h4>
                <ul className="space-y-2 text-sm text-gray-600 dark:text-gray-400">
                  <li>• Do not access, modify, or delete user data</li>
                  <li>• Do not perform denial of service attacks</li>
                  <li>• Report vulnerabilities responsibly</li>
                  <li>• Allow reasonable time for fix implementation</li>
                  <li>• One report per vulnerability</li>
                </ul>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default BugBounty;