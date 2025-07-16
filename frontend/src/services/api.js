import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Auth API
export const authAPI = {
  login: (credentials) => api.post('/api/auth/login', credentials),
  register: (userData) => api.post('/api/auth/register', userData),
  logout: () => api.post('/api/auth/logout'),
  getCurrentUser: () => api.get('/api/auth/me'),
  changePassword: (passwordData) => api.post('/api/auth/change-password', passwordData),
  getApiKey: () => api.get('/api/auth/api-key'),
  regenerateApiKey: () => api.post('/api/auth/regenerate-api-key'),
};

// Encryption API
export const encryptionAPI = {
  encrypt: (data) => api.post('/api/encryption/encrypt', data),
  decrypt: (data) => api.post('/api/encryption/decrypt', data),
  sign: (data) => api.post('/api/encryption/sign', data),
  verify: (data) => api.post('/api/encryption/verify', data),
  generateKeys: (data) => api.post('/api/encryption/generate-keys', data),
  getAlgorithms: () => api.get('/api/encryption/algorithms'),
  getStats: () => api.get('/api/encryption/stats'),
};

// Dashboard API
export const dashboardAPI = {
  getOverview: () => api.get('/api/dashboard/overview'),
  getSecurityStatus: () => api.get('/api/dashboard/security-status'),
  getBugBounty: () => api.get('/api/dashboard/bug-bounty'),
  getAnalytics: (params) => api.get('/api/dashboard/analytics', { params }),
  getAuditLogs: (params) => api.get('/api/dashboard/audit-logs', { params }),
  getNotifications: () => api.get('/api/dashboard/notifications'),
  markNotificationRead: (notificationId) => api.post(`/api/dashboard/notifications/${notificationId}/read`),
  getSystemHealth: () => api.get('/api/dashboard/system-health'),
};

// Bug Bounty API
export const bugBountyAPI = {
  submitReport: (reportData) => api.post('/api/dashboard/bug-bounty/submit', reportData),
  getReports: (params) => api.get('/api/bug-bounty/reports', { params }),
  getLeaderboard: () => api.get('/api/bug-bounty/leaderboard'),
  getGuidelines: () => api.get('/api/bug-bounty/guidelines'),
  getStatistics: () => api.get('/api/bug-bounty/statistics'),
};

// Threat Detection API
export const threatAPI = {
  scanThreat: (requestData) => api.post('/api/threat/scan', requestData),
  getThreats: (params) => api.get('/api/threat/threats', { params }),
  getStatistics: () => api.get('/api/threat/statistics'),
  updateThreatStatus: (threatId, status) => api.put(`/api/threat/threats/${threatId}/status`, { status }),
};

// Blockchain API
export const blockchainAPI = {
  getNetworkInfo: (chain) => api.get(`/api/blockchain/network/${chain}`),
  getBalance: (chain, address) => api.get(`/api/blockchain/balance/${chain}/${address}`),
  createTransaction: (transactionData) => api.post('/api/blockchain/transaction', transactionData),
  getTransactionStatus: (chain, txHash) => api.get(`/api/blockchain/transaction/${chain}/${txHash}`),
  deployContract: (contractData) => api.post('/api/blockchain/deploy-contract', contractData),
  callContract: (contractData) => api.post('/api/blockchain/call-contract', contractData),
};

// Health check
export const healthAPI = {
  check: () => api.get('/api/health'),
};

export default api;