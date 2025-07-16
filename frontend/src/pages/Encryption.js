import React, { useState, useEffect } from 'react';
import { encryptionAPI } from '../services/api';
import { 
  ShieldCheckIcon, 
  KeyIcon, 
  DocumentTextIcon, 
  ClipboardDocumentIcon,
  ArrowPathIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline';
import { CopyToClipboard } from 'react-copy-to-clipboard';
import toast from 'react-hot-toast';

const Encryption = () => {
  const [activeTab, setActiveTab] = useState('encrypt');
  const [algorithms, setAlgorithms] = useState([]);
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    data: '',
    encrypted_data: '',
    algorithm: 'hybrid',
    key_size: 256,
    public_key: '',
    private_key: '',
    signature: ''
  });
  const [result, setResult] = useState(null);

  useEffect(() => {
    const fetchAlgorithms = async () => {
      try {
        const response = await encryptionAPI.getAlgorithms();
        setAlgorithms(response.data);
      } catch (error) {
        toast.error('Failed to load algorithms');
      }
    };

    fetchAlgorithms();
  }, []);

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleEncrypt = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const response = await encryptionAPI.encrypt({
        data: formData.data,
        algorithm: formData.algorithm,
        key_size: formData.key_size
      });
      
      setResult(response.data);
      setFormData({
        ...formData,
        encrypted_data: response.data.encrypted_data,
        public_key: response.data.public_key || ''
      });
      
      toast.success('Encryption successful!');
    } catch (error) {
      toast.error('Encryption failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const handleDecrypt = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const response = await encryptionAPI.decrypt({
        encrypted_data: formData.encrypted_data,
        algorithm: formData.algorithm,
        private_key: formData.private_key
      });
      
      setResult(response.data);
      setFormData({
        ...formData,
        data: response.data.decrypted_data
      });
      
      toast.success('Decryption successful!');
    } catch (error) {
      toast.error('Decryption failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const handleSign = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const response = await encryptionAPI.sign({
        data: formData.data,
        algorithm: formData.algorithm,
        private_key: formData.private_key
      });
      
      setResult(response.data);
      setFormData({
        ...formData,
        signature: response.data.signature,
        public_key: response.data.public_key || ''
      });
      
      toast.success('Signing successful!');
    } catch (error) {
      toast.error('Signing failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const response = await encryptionAPI.verify({
        data: formData.data,
        signature: formData.signature,
        public_key: formData.public_key,
        algorithm: formData.algorithm
      });
      
      setResult(response.data);
      toast.success(`Verification ${response.data.valid ? 'successful' : 'failed'}!`);
    } catch (error) {
      toast.error('Verification failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateKeys = async () => {
    setLoading(true);
    
    try {
      const response = await encryptionAPI.generateKeys({
        algorithm: formData.algorithm,
        key_size: formData.key_size,
        purpose: 'encryption'
      });
      
      setFormData({
        ...formData,
        public_key: response.data.public_key,
        private_key: response.data.private_key || ''
      });
      
      toast.success('Keys generated successfully!');
    } catch (error) {
      toast.error('Key generation failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const tabs = [
    { id: 'encrypt', name: 'Encrypt', icon: ShieldCheckIcon },
    { id: 'decrypt', name: 'Decrypt', icon: KeyIcon },
    { id: 'sign', name: 'Sign', icon: DocumentTextIcon },
    { id: 'verify', name: 'Verify', icon: ClipboardDocumentIcon },
  ];

  const getSelectedAlgorithm = () => {
    return algorithms.find(alg => alg.algorithm === formData.algorithm) || {};
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="border-b border-gray-200 dark:border-gray-700 pb-4">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Encryption Tools</h1>
        <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
          Quantum-safe cryptographic operations
        </p>
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
                  : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300'
              } whitespace-nowrap py-2 px-1 border-b-2 font-medium text-sm flex items-center`}
            >
              <tab.icon className="h-5 w-5 mr-2" />
              {tab.name}
            </button>
          ))}
        </nav>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Form */}
        <div className="lg:col-span-2">
          <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
            <form onSubmit={
              activeTab === 'encrypt' ? handleEncrypt :
              activeTab === 'decrypt' ? handleDecrypt :
              activeTab === 'sign' ? handleSign :
              handleVerify
            }>
              {/* Algorithm Selection */}
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Algorithm
                </label>
                <select
                  name="algorithm"
                  value={formData.algorithm}
                  onChange={handleInputChange}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                >
                  <option value="hybrid">Hybrid (Recommended)</option>
                  <option value="kyber">Kyber (Post-Quantum)</option>
                  <option value="dilithium">Dilithium (Signatures)</option>
                  <option value="aes">AES (Classical)</option>
                  <option value="rsa">RSA (Classical)</option>
                </select>
              </div>

              {/* Key Size */}
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Key Size
                </label>
                <select
                  name="key_size"
                  value={formData.key_size}
                  onChange={handleInputChange}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                >
                  <option value={256}>256 bits</option>
                  <option value={512}>512 bits</option>
                  <option value={1024}>1024 bits</option>
                  <option value={2048}>2048 bits</option>
                </select>
              </div>

              {/* Data Input */}
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  {activeTab === 'encrypt' || activeTab === 'sign' ? 'Data to ' + activeTab : 
                   activeTab === 'decrypt' ? 'Encrypted Data' : 'Original Data'}
                </label>
                <textarea
                  name={activeTab === 'decrypt' ? 'encrypted_data' : 'data'}
                  value={activeTab === 'decrypt' ? formData.encrypted_data : formData.data}
                  onChange={handleInputChange}
                  rows={6}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                  placeholder={`Enter ${activeTab === 'decrypt' ? 'encrypted' : 'plain'} text here...`}
                />
              </div>

              {/* Key Inputs */}
              {(activeTab === 'decrypt' || activeTab === 'sign') && (
                <div className="mb-4">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Private Key
                  </label>
                  <textarea
                    name="private_key"
                    value={formData.private_key}
                    onChange={handleInputChange}
                    rows={4}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                    placeholder="Enter private key..."
                  />
                </div>
              )}

              {activeTab === 'verify' && (
                <>
                  <div className="mb-4">
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Signature
                    </label>
                    <textarea
                      name="signature"
                      value={formData.signature}
                      onChange={handleInputChange}
                      rows={4}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                      placeholder="Enter signature..."
                    />
                  </div>
                  <div className="mb-4">
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Public Key
                    </label>
                    <textarea
                      name="public_key"
                      value={formData.public_key}
                      onChange={handleInputChange}
                      rows={4}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                      placeholder="Enter public key..."
                    />
                  </div>
                </>
              )}

              {/* Action Buttons */}
              <div className="flex space-x-3">
                <button
                  type="submit"
                  disabled={loading}
                  className="flex-1 bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-4 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
                >
                  {loading ? (
                    <ArrowPathIcon className="h-5 w-5 animate-spin mx-auto" />
                  ) : (
                    activeTab.charAt(0).toUpperCase() + activeTab.slice(1)
                  )}
                </button>
                
                <button
                  type="button"
                  onClick={handleGenerateKeys}
                  disabled={loading}
                  className="bg-gray-600 hover:bg-gray-700 text-white font-medium py-2 px-4 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 disabled:opacity-50"
                >
                  Generate Keys
                </button>
              </div>
            </form>
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Algorithm Info */}
          <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4 flex items-center">
              <InformationCircleIcon className="h-5 w-5 mr-2" />
              Algorithm Info
            </h3>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-500 dark:text-gray-400">Type:</span>
                <span className="text-gray-900 dark:text-white">{getSelectedAlgorithm().type || 'N/A'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500 dark:text-gray-400">Quantum Safe:</span>
                <span className={`font-medium ${getSelectedAlgorithm().quantum_resistant ? 'text-green-600' : 'text-red-600'}`}>
                  {getSelectedAlgorithm().quantum_resistant ? 'Yes' : 'No'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500 dark:text-gray-400">Security Level:</span>
                <span className="text-gray-900 dark:text-white">{getSelectedAlgorithm().security_level || 'N/A'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500 dark:text-gray-400">Performance:</span>
                <span className="text-gray-900 dark:text-white">{getSelectedAlgorithm().performance_rating || 'N/A'}</span>
              </div>
            </div>
          </div>

          {/* Result Display */}
          {result && (
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                Result
              </h3>
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-500 dark:text-gray-400">Processing Time:</span>
                  <span className="text-sm text-gray-900 dark:text-white">{result.processing_time?.toFixed(3)}s</span>
                </div>
                
                {result.quantum_resistance_score && (
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-500 dark:text-gray-400">Quantum Resistance:</span>
                    <span className="text-sm text-green-600">{(result.quantum_resistance_score * 100).toFixed(1)}%</span>
                  </div>
                )}
                
                {result.valid !== undefined && (
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-500 dark:text-gray-400">Valid:</span>
                    <span className={`text-sm font-medium ${result.valid ? 'text-green-600' : 'text-red-600'}`}>
                      {result.valid ? 'Yes' : 'No'}
                    </span>
                  </div>
                )}
                
                {result.ai_recommendation && (
                  <div className="mt-4 p-3 bg-blue-50 dark:bg-blue-900 rounded-md">
                    <p className="text-sm text-blue-800 dark:text-blue-200">
                      <strong>AI Recommendation:</strong> {result.ai_recommendation}
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Copy Actions */}
          {(formData.public_key || formData.private_key || formData.signature) && (
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                Quick Actions
              </h3>
              <div className="space-y-2">
                {formData.public_key && (
                  <CopyToClipboard text={formData.public_key} onCopy={() => toast.success('Public key copied!')}>
                    <button className="w-full text-left px-3 py-2 text-sm bg-gray-50 dark:bg-gray-700 rounded-md hover:bg-gray-100 dark:hover:bg-gray-600">
                      Copy Public Key
                    </button>
                  </CopyToClipboard>
                )}
                {formData.private_key && (
                  <CopyToClipboard text={formData.private_key} onCopy={() => toast.success('Private key copied!')}>
                    <button className="w-full text-left px-3 py-2 text-sm bg-gray-50 dark:bg-gray-700 rounded-md hover:bg-gray-100 dark:hover:bg-gray-600">
                      Copy Private Key
                    </button>
                  </CopyToClipboard>
                )}
                {formData.signature && (
                  <CopyToClipboard text={formData.signature} onCopy={() => toast.success('Signature copied!')}>
                    <button className="w-full text-left px-3 py-2 text-sm bg-gray-50 dark:bg-gray-700 rounded-md hover:bg-gray-100 dark:hover:bg-gray-600">
                      Copy Signature
                    </button>
                  </CopyToClipboard>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Encryption;