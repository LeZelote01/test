import React, { useState, useEffect } from 'react';
import { ExclamationTriangleIcon, ShieldCheckIcon, EyeIcon, CpuChipIcon } from '@heroicons/react/24/outline';

const ThreatDetection = () => {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanData, setScanData] = useState({
    payload: '',
    ip_address: '',
    user_agent: ''
  });

  useEffect(() => {
    // Mock data for demonstration
    const mockThreats = [
      {
        id: 1,
        type: 'Quantum Attack',
        level: 'high',
        description: 'Potential Shor algorithm usage detected',
        timestamp: '2024-01-15T10:30:00Z',
        source_ip: '192.168.1.100',
        blocked: true
      },
      {
        id: 2,
        type: 'Anomalous Pattern',
        level: 'medium',
        description: 'Unusual encryption request pattern',
        timestamp: '2024-01-15T09:45:00Z',
        source_ip: '10.0.0.50',
        blocked: false
      },
      {
        id: 3,
        type: 'Brute Force',
        level: 'low',
        description: 'Multiple failed authentication attempts',
        timestamp: '2024-01-15T08:15:00Z',
        source_ip: '203.0.113.1',
        blocked: true
      }
    ];
    
    setThreats(mockThreats);
    setLoading(false);
  }, []);

  const handleScan = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    // Simulate scan
    setTimeout(() => {
      const newThreat = {
        id: threats.length + 1,
        type: 'Manual Scan',
        level: Math.random() > 0.7 ? 'high' : Math.random() > 0.4 ? 'medium' : 'low',
        description: 'Manual threat scan completed',
        timestamp: new Date().toISOString(),
        source_ip: scanData.ip_address || '127.0.0.1',
        blocked: false
      };
      
      setThreats([newThreat, ...threats]);
      setLoading(false);
    }, 2000);
  };

  const getThreatColor = (level) => {
    switch (level) {
      case 'high': return 'text-red-600 bg-red-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getThreatIcon = (type) => {
    switch (type) {
      case 'Quantum Attack': return CpuChipIcon;
      case 'Anomalous Pattern': return EyeIcon;
      default: return ExclamationTriangleIcon;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-gray-200 dark:border-gray-700 pb-4">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Threat Detection</h1>
        <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
          AI-powered quantum threat detection and monitoring
        </p>
      </div>

      {/* Threat Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Total Threats</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{threats.length}</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <div className="flex items-center">
            <CpuChipIcon className="h-8 w-8 text-purple-500" />
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Quantum Threats</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {threats.filter(t => t.type === 'Quantum Attack').length}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <div className="flex items-center">
            <ShieldCheckIcon className="h-8 w-8 text-green-500" />
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Blocked</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {threats.filter(t => t.blocked).length}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
          <div className="flex items-center">
            <EyeIcon className="h-8 w-8 text-blue-500" />
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Monitoring</p>
              <p className="text-2xl font-bold text-green-500">Active</p>
            </div>
          </div>
        </div>
      </div>

      {/* Manual Scan */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Manual Threat Scan</h3>
        <form onSubmit={handleScan} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Request Payload
            </label>
            <textarea
              value={scanData.payload}
              onChange={(e) => setScanData({...scanData, payload: e.target.value})}
              rows={4}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
              placeholder="Enter request payload to scan..."
            />
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Source IP
              </label>
              <input
                type="text"
                value={scanData.ip_address}
                onChange={(e) => setScanData({...scanData, ip_address: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                placeholder="192.168.1.100"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                User Agent
              </label>
              <input
                type="text"
                value={scanData.user_agent}
                onChange={(e) => setScanData({...scanData, user_agent: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                placeholder="Mozilla/5.0..."
              />
            </div>
          </div>
          
          <button
            type="submit"
            disabled={loading}
            className="bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-4 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
          >
            {loading ? 'Scanning...' : 'Scan for Threats'}
          </button>
        </form>
      </div>

      {/* Threats List */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">Recent Threats</h3>
        </div>
        
        <div className="divide-y divide-gray-200 dark:divide-gray-700">
          {threats.map((threat) => {
            const ThreatIcon = getThreatIcon(threat.type);
            return (
              <div key={threat.id} className="p-6">
                <div className="flex items-start space-x-4">
                  <div className="flex-shrink-0">
                    <ThreatIcon className="h-6 w-6 text-gray-400" />
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <p className="text-sm font-medium text-gray-900 dark:text-white">
                          {threat.type}
                        </p>
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getThreatColor(threat.level)}`}>
                          {threat.level}
                        </span>
                        {threat.blocked && (
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium text-red-800 bg-red-100">
                            Blocked
                          </span>
                        )}
                      </div>
                      
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {new Date(threat.timestamp).toLocaleString()}
                      </p>
                    </div>
                    
                    <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                      {threat.description}
                    </p>
                    
                    <div className="mt-2 flex items-center space-x-4 text-sm text-gray-500 dark:text-gray-400">
                      <span>Source: {threat.source_ip}</span>
                      <span>•</span>
                      <span>ID: {threat.id}</span>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default ThreatDetection;