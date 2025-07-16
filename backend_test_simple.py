#!/usr/bin/env python3
"""
Simplified Backend Testing for QuantumGate
Tests core backend APIs without complex post-quantum dependencies
"""
import requests
import json
import time
from typing import Dict, Any

# Configuration
BACKEND_URL = 'http://localhost:8001'
TEST_USER_DATA = {
    "username": "quantum_tester",
    "email": "tester@quantumgate.com", 
    "password": "SecurePass123!",
    "full_name": "QuantumGate Tester",
    "organization": "Test Organization",
    "country": "US",
    "preferred_language": "en"
}

class QuantumGateSimpleTester:
    def __init__(self):
        self.base_url = BACKEND_URL
        self.access_token = None
        self.user_id = None
        self.test_results = []
        
    def log_test(self, test_name: str, success: bool, message: str = ""):
        """Log test result."""
        result = {
            "test": test_name,
            "success": success,
            "message": message,
            "timestamp": time.time()
        }
        self.test_results.append(result)
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}: {message}")
    
    def make_request(self, method: str, endpoint: str, data: Dict = None, 
                    headers: Dict = None, auth_required: bool = False) -> requests.Response:
        """Make HTTP request with proper headers."""
        url = f"{self.base_url}{endpoint}"
        request_headers = {"Content-Type": "application/json"}
        
        if headers:
            request_headers.update(headers)
            
        if auth_required and self.access_token:
            request_headers["Authorization"] = f"Bearer {self.access_token}"
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=request_headers)
            elif method.upper() == "POST":
                response = requests.post(url, json=data, headers=request_headers)
            else:
                raise ValueError(f"Unsupported method: {method}")
                
            return response
        except Exception as e:
            print(f"Request failed: {e}")
            raise
    
    def test_health_endpoint(self):
        """Test health check endpoint."""
        try:
            response = self.make_request("GET", "/api/health")
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "healthy":
                    self.log_test("Health Check", True, "Backend is healthy")
                else:
                    self.log_test("Health Check", False, "Unexpected health status")
            else:
                self.log_test("Health Check", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("Health Check", False, f"Exception: {str(e)}")
    
    def test_root_endpoint(self):
        """Test root endpoint."""
        try:
            response = self.make_request("GET", "/api/")
            
            if response.status_code == 200:
                data = response.json()
                if "QuantumGate" in data.get("message", ""):
                    self.log_test("Root Endpoint", True, "Root endpoint working")
                else:
                    self.log_test("Root Endpoint", False, "Unexpected response")
            else:
                self.log_test("Root Endpoint", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("Root Endpoint", False, f"Exception: {str(e)}")
    
    def test_user_registration(self):
        """Test user registration."""
        try:
            response = self.make_request("POST", "/api/auth/register", TEST_USER_DATA)
            
            if response.status_code == 201:
                data = response.json()
                if data.get("username") == TEST_USER_DATA["username"]:
                    self.user_id = data.get("id")
                    self.log_test("User Registration", True, "User registered successfully")
                else:
                    self.log_test("User Registration", False, "Invalid registration response")
            elif response.status_code == 400:
                # User might already exist
                error_data = response.json()
                if "already" in error_data.get("detail", "").lower():
                    self.log_test("User Registration", True, "User already exists (expected)")
                else:
                    self.log_test("User Registration", False, f"Registration failed: {error_data}")
            else:
                self.log_test("User Registration", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("User Registration", False, f"Exception: {str(e)}")
    
    def test_user_login(self):
        """Test user login."""
        try:
            login_data = {
                "username": TEST_USER_DATA["username"],
                "password": TEST_USER_DATA["password"]
            }
            response = self.make_request("POST", "/api/auth/login", login_data)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("access_token"):
                    self.access_token = data["access_token"]
                    self.user_id = data.get("user", {}).get("id")
                    self.log_test("User Login", True, "Login successful")
                else:
                    self.log_test("User Login", False, "No access token in response")
            else:
                self.log_test("User Login", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("User Login", False, f"Exception: {str(e)}")
    
    def test_get_current_user(self):
        """Test getting current user info."""
        try:
            response = self.make_request("GET", "/api/auth/me", auth_required=True)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("username") == TEST_USER_DATA["username"]:
                    self.log_test("Get Current User", True, "User info retrieved")
                else:
                    self.log_test("Get Current User", False, "Unexpected user data")
            else:
                self.log_test("Get Current User", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("Get Current User", False, f"Exception: {str(e)}")
    
    def test_encryption_algorithms(self):
        """Test getting available algorithms."""
        try:
            response = self.make_request("GET", "/api/encryption/algorithms")
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) > 0:
                    algorithms = [alg.get("algorithm") for alg in data]
                    expected_algorithms = ["kyber", "dilithium", "aes", "rsa", "hybrid"]
                    
                    if any(alg in algorithms for alg in expected_algorithms):
                        self.log_test("Encryption Algorithms", True, f"Found {len(data)} algorithms")
                    else:
                        self.log_test("Encryption Algorithms", False, "No expected algorithms found")
                else:
                    self.log_test("Encryption Algorithms", False, "Empty or invalid response")
            else:
                self.log_test("Encryption Algorithms", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("Encryption Algorithms", False, f"Exception: {str(e)}")
    
    def test_aes_encryption(self):
        """Test AES encryption."""
        try:
            encryption_data = {
                "data": "Sensitive financial data requiring AES encryption protection",
                "algorithm": "aes",
                "options": {}
            }
            response = self.make_request("POST", "/api/encryption/encrypt", 
                                       encryption_data, auth_required=True)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("encrypted_data") and data.get("algorithm") == "aes":
                    self.log_test("AES Encryption", True, "AES encryption successful")
                    return data
                else:
                    self.log_test("AES Encryption", False, "Invalid encryption response")
            else:
                self.log_test("AES Encryption", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("AES Encryption", False, f"Exception: {str(e)}")
        return None
    
    def test_kyber_encryption(self):
        """Test Kyber encryption."""
        try:
            encryption_data = {
                "data": "Top secret quantum research data requiring post-quantum protection",
                "algorithm": "kyber",
                "options": {}
            }
            response = self.make_request("POST", "/api/encryption/encrypt", 
                                       encryption_data, auth_required=True)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("encrypted_data") and data.get("algorithm") == "kyber":
                    self.log_test("Kyber Encryption", True, "Kyber encryption successful")
                    return data
                else:
                    self.log_test("Kyber Encryption", False, "Invalid encryption response")
            else:
                self.log_test("Kyber Encryption", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("Kyber Encryption", False, f"Exception: {str(e)}")
        return None
    
    def test_encryption_stats(self):
        """Test encryption statistics."""
        try:
            response = self.make_request("GET", "/api/encryption/stats", auth_required=True)
            
            if response.status_code == 200:
                data = response.json()
                if "total_operations" in data:
                    self.log_test("Encryption Stats", True, "Statistics retrieved")
                else:
                    self.log_test("Encryption Stats", False, "Invalid stats response")
            else:
                self.log_test("Encryption Stats", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("Encryption Stats", False, f"Exception: {str(e)}")
    
    def test_dashboard_overview(self):
        """Test dashboard overview."""
        try:
            response = self.make_request("GET", "/api/dashboard/overview", auth_required=True)
            
            if response.status_code == 200:
                data = response.json()
                if "encryption_stats" in data and "threat_stats" in data:
                    self.log_test("Dashboard Overview", True, "Dashboard data retrieved")
                else:
                    self.log_test("Dashboard Overview", False, "Invalid dashboard response")
            else:
                self.log_test("Dashboard Overview", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("Dashboard Overview", False, f"Exception: {str(e)}")
    
    def test_security_status(self):
        """Test security status endpoint."""
        try:
            response = self.make_request("GET", "/api/dashboard/security-status", auth_required=True)
            
            if response.status_code == 200:
                data = response.json()
                if "security_score" in data and "recommendations" in data:
                    self.log_test("Security Status", True, "Security status retrieved")
                else:
                    self.log_test("Security Status", False, "Invalid security status response")
            else:
                self.log_test("Security Status", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("Security Status", False, f"Exception: {str(e)}")
    
    def test_bug_bounty_dashboard(self):
        """Test bug bounty dashboard."""
        try:
            response = self.make_request("GET", "/api/dashboard/bug-bounty", auth_required=True)
            
            if response.status_code == 200:
                data = response.json()
                if "user_stats" in data and "program_stats" in data:
                    self.log_test("Bug Bounty Dashboard", True, "Bug bounty data retrieved")
                else:
                    self.log_test("Bug Bounty Dashboard", False, "Invalid bug bounty response")
            else:
                self.log_test("Bug Bounty Dashboard", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("Bug Bounty Dashboard", False, f"Exception: {str(e)}")
    
    def test_submit_bug_report(self):
        """Test bug report submission."""
        try:
            bug_report = {
                "title": "Potential Authentication Bypass Vulnerability",
                "description": "Discovered a potential authentication bypass in the login system that could allow unauthorized access",
                "severity": "high",
                "category": "general",
                "steps_to_reproduce": "1. Navigate to login endpoint\n2. Send malformed authentication request\n3. Observe system response",
                "expected_behavior": "Should reject invalid authentication attempts",
                "actual_behavior": "System may allow unauthorized access under specific conditions",
                "impact": "Could lead to complete system compromise",
                "proof_of_concept": "Technical details of the vulnerability exploitation",
                "affected_components": ["authentication", "user_management", "security"]
            }
            response = self.make_request("POST", "/api/dashboard/bug-bounty/submit", 
                                       bug_report, auth_required=True)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "submitted":
                    self.log_test("Bug Report Submission", True, "Bug report submitted")
                else:
                    self.log_test("Bug Report Submission", False, "Invalid submission response")
            else:
                self.log_test("Bug Report Submission", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("Bug Report Submission", False, f"Exception: {str(e)}")
    
    def test_analytics(self):
        """Test analytics endpoint."""
        try:
            response = self.make_request("GET", "/api/dashboard/analytics?days=7", auth_required=True)
            
            if response.status_code == 200:
                data = response.json()
                if "encryption_analytics" in data and "threat_analytics" in data:
                    self.log_test("Analytics", True, "Analytics data retrieved")
                else:
                    self.log_test("Analytics", False, "Invalid analytics response")
            else:
                self.log_test("Analytics", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("Analytics", False, f"Exception: {str(e)}")
    
    def test_audit_logs(self):
        """Test audit logs endpoint."""
        try:
            response = self.make_request("GET", "/api/dashboard/audit-logs?limit=10", auth_required=True)
            
            if response.status_code == 200:
                data = response.json()
                if "logs" in data and isinstance(data["logs"], list):
                    self.log_test("Audit Logs", True, "Audit logs retrieved")
                else:
                    self.log_test("Audit Logs", False, "Invalid audit logs response")
            else:
                self.log_test("Audit Logs", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("Audit Logs", False, f"Exception: {str(e)}")
    
    def test_notifications(self):
        """Test notifications endpoint."""
        try:
            response = self.make_request("GET", "/api/dashboard/notifications", auth_required=True)
            
            if response.status_code == 200:
                data = response.json()
                if "notifications" in data and "unread_count" in data:
                    self.log_test("Notifications", True, "Notifications retrieved")
                else:
                    self.log_test("Notifications", False, "Invalid notifications response")
            else:
                self.log_test("Notifications", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("Notifications", False, f"Exception: {str(e)}")
    
    def test_system_health(self):
        """Test system health endpoint."""
        try:
            response = self.make_request("GET", "/api/dashboard/system-health", auth_required=True)
            
            if response.status_code == 200:
                data = response.json()
                if "overall_status" in data and "services" in data:
                    self.log_test("System Health", True, "System health retrieved")
                else:
                    self.log_test("System Health", False, "Invalid system health response")
            else:
                self.log_test("System Health", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("System Health", False, f"Exception: {str(e)}")

    def test_user_logout(self):
        """Test user logout."""
        try:
            response = self.make_request("POST", "/api/auth/logout", auth_required=True)
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data:
                    self.log_test("User Logout", True, "Logout successful")
                else:
                    self.log_test("User Logout", False, "Invalid logout response")
            else:
                self.log_test("User Logout", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("User Logout", False, f"Exception: {str(e)}")
    
    def run_all_tests(self):
        """Run all backend tests."""
        print("🚀 Starting QuantumGate Backend Testing (Simplified)...")
        print(f"Backend URL: {self.base_url}")
        print("=" * 60)
        
        # Basic connectivity tests
        self.test_health_endpoint()
        self.test_root_endpoint()
        
        # Authentication tests
        print("\n🔐 Testing Authentication...")
        self.test_user_registration()
        self.test_user_login()
        
        if self.access_token:
            # Authenticated endpoint tests
            print("\n👤 Testing User Management...")
            self.test_get_current_user()
            
            # Encryption tests
            print("\n🔒 Testing Encryption...")
            self.test_encryption_algorithms()
            self.test_aes_encryption()
            self.test_kyber_encryption()
            self.test_encryption_stats()
            
            # Dashboard tests
            print("\n📊 Testing Dashboard...")
            self.test_dashboard_overview()
            self.test_security_status()
            self.test_bug_bounty_dashboard()
            self.test_submit_bug_report()
            self.test_analytics()
            self.test_audit_logs()
            self.test_notifications()
            self.test_system_health()
            
            # Logout test
            self.test_user_logout()
        else:
            print("⚠️  Skipping authenticated tests - no access token")
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary."""
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result["success"])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests > 0:
            print("\n❌ FAILED TESTS:")
            for result in self.test_results:
                if not result["success"]:
                    print(f"  - {result['test']}: {result['message']}")
        
        print("\n🎯 CRITICAL FUNCTIONALITY STATUS:")
        critical_tests = [
            "Health Check", "User Registration", "User Login", 
            "AES Encryption", "Kyber Encryption", "Dashboard Overview",
            "Security Status", "Bug Report Submission"
        ]
        
        for test_name in critical_tests:
            test_result = next((r for r in self.test_results if r["test"] == test_name), None)
            if test_result:
                status = "✅" if test_result["success"] else "❌"
                print(f"  {status} {test_name}")
            else:
                print(f"  ⚠️  {test_name} (not tested)")

def main():
    """Main test execution."""
    tester = QuantumGateSimpleTester()
    tester.run_all_tests()

if __name__ == "__main__":
    main()