"""
Bug Bounty Service for QuantumGate.
Handles bug bounty program operations.
"""
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import logging

from database.models import BugBounty, BugBountyStatus
from config import settings
from utils.logger import log_operation, log_error

logger = logging.getLogger(__name__)

class BugBountyService:
    """Service for managing bug bounty program."""
    
    def __init__(self):
        self.reward_matrix = {
            "critical": {"min": 5000, "max": 20000},
            "high": {"min": 2000, "max": 5000},
            "medium": {"min": 500, "max": 2000},
            "low": {"min": 100, "max": 500}
        }
    
    async def submit_bug_report(self, report_data: Dict[str, Any], 
                               user_id: str) -> Dict[str, Any]:
        """Submit a new bug report."""
        try:
            # Validate and process report
            processed_report = self._process_bug_report(report_data, user_id)
            
            # Calculate initial reward estimate
            reward_estimate = self._calculate_reward_estimate(processed_report)
            
            # Generate report ID
            report_id = str(uuid.uuid4())
            
            # Create bug bounty record
            bug_bounty = {
                "id": report_id,
                "title": processed_report["title"],
                "description": processed_report["description"],
                "severity": processed_report["severity"],
                "category": processed_report["category"],
                "reporter_id": user_id,
                "reporter_name": processed_report["reporter_name"],
                "reporter_email": processed_report["reporter_email"],
                "steps_to_reproduce": processed_report["steps_to_reproduce"],
                "proof_of_concept": processed_report.get("proof_of_concept"),
                "affected_components": processed_report["affected_components"],
                "status": BugBountyStatus.SUBMITTED.value,
                "reward_amount": reward_estimate,
                "reward_currency": "USD",
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            
            log_operation(
                logger, user_id, "bug_report_submitted",
                {
                    "report_id": report_id,
                    "severity": processed_report["severity"],
                    "category": processed_report["category"]
                }
            )
            
            return {
                "report_id": report_id,
                "status": BugBountyStatus.SUBMITTED.value,
                "reward_estimate": reward_estimate,
                "message": "Bug report submitted successfully",
                "next_steps": [
                    "Your report will be reviewed within 48 hours",
                    "You will receive email updates on the status",
                    "If accepted, testing will begin immediately"
                ]
            }
            
        except Exception as e:
            log_error(logger, e, user_id, "bug_report_submission")
            raise
    
    def _process_bug_report(self, report_data: Dict[str, Any], 
                           user_id: str) -> Dict[str, Any]:
        """Process and validate bug report data."""
        required_fields = [
            "title", "description", "severity", "category",
            "reporter_name", "reporter_email", "steps_to_reproduce",
            "affected_components"
        ]
        
        for field in required_fields:
            if field not in report_data:
                raise ValueError(f"Missing required field: {field}")
        
        # Validate severity
        valid_severities = ["low", "medium", "high", "critical"]
        if report_data["severity"] not in valid_severities:
            raise ValueError(f"Invalid severity: {report_data['severity']}")
        
        # Validate category
        valid_categories = ["crypto", "ai", "blockchain", "general"]
        if report_data["category"] not in valid_categories:
            raise ValueError(f"Invalid category: {report_data['category']}")
        
        # Clean and validate steps
        steps = report_data["steps_to_reproduce"]
        if isinstance(steps, str):
            steps = [step.strip() for step in steps.split("\n") if step.strip()]
        
        if not steps:
            raise ValueError("Steps to reproduce cannot be empty")
        
        # Clean and validate affected components
        components = report_data["affected_components"]
        if isinstance(components, str):
            components = [comp.strip() for comp in components.split(",") if comp.strip()]
        
        if not components:
            raise ValueError("Affected components cannot be empty")
        
        return {
            "title": report_data["title"].strip(),
            "description": report_data["description"].strip(),
            "severity": report_data["severity"],
            "category": report_data["category"],
            "reporter_name": report_data["reporter_name"].strip(),
            "reporter_email": report_data["reporter_email"].strip(),
            "steps_to_reproduce": steps,
            "proof_of_concept": report_data.get("proof_of_concept", "").strip(),
            "affected_components": components
        }
    
    def _calculate_reward_estimate(self, report_data: Dict[str, Any]) -> float:
        """Calculate reward estimate based on bug report."""
        severity = report_data["severity"]
        category = report_data["category"]
        
        # Base reward from severity
        base_reward = self.reward_matrix[severity]["min"]
        max_reward = self.reward_matrix[severity]["max"]
        
        # Category multipliers
        category_multipliers = {
            "crypto": 1.5,  # Crypto bugs are more valuable
            "ai": 1.3,
            "blockchain": 1.4,
            "general": 1.0
        }
        
        multiplier = category_multipliers.get(category, 1.0)
        
        # Calculate final reward
        reward = base_reward * multiplier
        
        # Ensure within bounds
        reward = min(reward, max_reward * multiplier)
        reward = max(reward, self.reward_matrix[severity]["min"])
        
        return round(reward, 2)
    
    async def review_bug_report(self, report_id: str, reviewer_id: str,
                               review_data: Dict[str, Any]) -> Dict[str, Any]:
        """Review a bug report."""
        try:
            # Process review
            new_status = review_data["status"]
            review_notes = review_data.get("review_notes", "")
            final_reward = review_data.get("reward_amount")
            
            # Validate status
            valid_statuses = [status.value for status in BugBountyStatus]
            if new_status not in valid_statuses:
                raise ValueError(f"Invalid status: {new_status}")
            
            # Update record (in production, this would update the database)
            update_data = {
                "status": new_status,
                "reviewer_id": reviewer_id,
                "review_notes": review_notes,
                "updated_at": datetime.utcnow()
            }
            
            if final_reward is not None:
                update_data["reward_amount"] = final_reward
            
            log_operation(
                logger, reviewer_id, "bug_report_reviewed",
                {
                    "report_id": report_id,
                    "new_status": new_status,
                    "reward_amount": final_reward
                }
            )
            
            return {
                "report_id": report_id,
                "status": new_status,
                "review_notes": review_notes,
                "reward_amount": final_reward,
                "message": "Bug report reviewed successfully"
            }
            
        except Exception as e:
            log_error(logger, e, reviewer_id, "bug_report_review")
            raise
    
    async def get_bug_reports(self, filters: Optional[Dict[str, Any]] = None,
                             user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get bug reports with optional filtering."""
        try:
            # In production, this would query the database
            # For now, return mock data
            mock_reports = [
                {
                    "id": "report-1",
                    "title": "SQL Injection in User Authentication",
                    "severity": "high",
                    "category": "general",
                    "status": "under_review",
                    "reporter_name": "John Doe",
                    "reward_amount": 3000,
                    "created_at": datetime.utcnow() - timedelta(days=2)
                },
                {
                    "id": "report-2",
                    "title": "Kyber Key Generation Vulnerability",
                    "severity": "critical",
                    "category": "crypto",
                    "status": "accepted",
                    "reporter_name": "Jane Smith",
                    "reward_amount": 8000,
                    "created_at": datetime.utcnow() - timedelta(days=5)
                }
            ]
            
            # Apply filters if provided
            if filters:
                filtered_reports = []
                for report in mock_reports:
                    if self._matches_filters(report, filters):
                        filtered_reports.append(report)
                mock_reports = filtered_reports
            
            return mock_reports
            
        except Exception as e:
            log_error(logger, e, user_id, "get_bug_reports")
            raise
    
    def _matches_filters(self, report: Dict[str, Any], 
                        filters: Dict[str, Any]) -> bool:
        """Check if report matches filters."""
        for key, value in filters.items():
            if key in report and report[key] != value:
                return False
        return True
    
    async def get_bug_statistics(self) -> Dict[str, Any]:
        """Get bug bounty program statistics."""
        try:
            # In production, this would query the database
            return {
                "total_reports": 156,
                "reports_by_status": {
                    "submitted": 45,
                    "under_review": 23,
                    "accepted": 67,
                    "rejected": 15,
                    "fixed": 45,
                    "paid": 40
                },
                "reports_by_severity": {
                    "low": 45,
                    "medium": 67,
                    "high": 34,
                    "critical": 10
                },
                "reports_by_category": {
                    "crypto": 45,
                    "ai": 23,
                    "blockchain": 34,
                    "general": 54
                },
                "total_rewards_paid": 245000,
                "average_reward": 3500,
                "top_reporters": [
                    {"name": "Alice Johnson", "reports": 12, "total_reward": 25000},
                    {"name": "Bob Wilson", "reports": 8, "total_reward": 18000},
                    {"name": "Charlie Brown", "reports": 6, "total_reward": 15000}
                ],
                "recent_trends": {
                    "submissions_this_month": 23,
                    "average_resolution_time": 5.2,  # days
                    "acceptance_rate": 0.72
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get bug statistics: {e}")
            return {}
    
    async def process_reward_payment(self, report_id: str, 
                                   payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process reward payment for a bug report."""
        try:
            # Validate payment data
            required_fields = ["payment_method", "amount", "currency"]
            for field in required_fields:
                if field not in payment_data:
                    raise ValueError(f"Missing required field: {field}")
            
            # In production, integrate with payment processor
            # For now, simulate payment processing
            payment_id = str(uuid.uuid4())
            
            # Update bug report status
            update_data = {
                "status": BugBountyStatus.PAID.value,
                "paid_at": datetime.utcnow(),
                "payment_id": payment_id,
                "updated_at": datetime.utcnow()
            }
            
            log_operation(
                logger, None, "reward_payment_processed",
                {
                    "report_id": report_id,
                    "payment_id": payment_id,
                    "amount": payment_data["amount"],
                    "currency": payment_data["currency"]
                }
            )
            
            return {
                "payment_id": payment_id,
                "status": "completed",
                "amount": payment_data["amount"],
                "currency": payment_data["currency"],
                "processed_at": datetime.utcnow().isoformat(),
                "message": "Reward payment processed successfully"
            }
            
        except Exception as e:
            log_error(logger, e, None, "reward_payment_processing")
            raise
    
    async def get_leaderboard(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get bug bounty leaderboard."""
        try:
            # In production, this would query the database
            leaderboard = [
                {
                    "rank": 1,
                    "reporter_name": "Alice Johnson",
                    "total_reports": 12,
                    "total_reward": 25000,
                    "avg_severity": "high",
                    "success_rate": 0.92
                },
                {
                    "rank": 2,
                    "reporter_name": "Bob Wilson",
                    "total_reports": 8,
                    "total_reward": 18000,
                    "avg_severity": "medium",
                    "success_rate": 0.88
                },
                {
                    "rank": 3,
                    "reporter_name": "Charlie Brown",
                    "total_reports": 6,
                    "total_reward": 15000,
                    "avg_severity": "high",
                    "success_rate": 0.83
                },
                {
                    "rank": 4,
                    "reporter_name": "Diana Prince",
                    "total_reports": 10,
                    "total_reward": 12000,
                    "avg_severity": "medium",
                    "success_rate": 0.80
                },
                {
                    "rank": 5,
                    "reporter_name": "Eve Adams",
                    "total_reports": 7,
                    "total_reward": 9500,
                    "avg_severity": "low",
                    "success_rate": 0.86
                }
            ]
            
            return leaderboard[:limit]
            
        except Exception as e:
            logger.error(f"Failed to get leaderboard: {e}")
            return []
    
    def get_reward_guidelines(self) -> Dict[str, Any]:
        """Get bug bounty reward guidelines."""
        return {
            "reward_matrix": self.reward_matrix,
            "guidelines": {
                "crypto": {
                    "description": "Vulnerabilities in cryptographic implementations",
                    "examples": [
                        "Kyber key generation flaws",
                        "Dilithium signature bypass",
                        "Hybrid encryption weaknesses"
                    ],
                    "multiplier": 1.5
                },
                "ai": {
                    "description": "AI/ML model vulnerabilities",
                    "examples": [
                        "Threat detection bypass",
                        "Model poisoning attacks",
                        "Algorithm recommendation manipulation"
                    ],
                    "multiplier": 1.3
                },
                "blockchain": {
                    "description": "Blockchain integration vulnerabilities",
                    "examples": [
                        "Smart contract bugs",
                        "Transaction replay attacks",
                        "Quantum protection bypass"
                    ],
                    "multiplier": 1.4
                },
                "general": {
                    "description": "General application vulnerabilities",
                    "examples": [
                        "Authentication bypass",
                        "SQL injection",
                        "Cross-site scripting"
                    ],
                    "multiplier": 1.0
                }
            },
            "submission_requirements": [
                "Clear vulnerability description",
                "Step-by-step reproduction",
                "Proof of concept (if applicable)",
                "Affected components list",
                "Suggested fix (optional)"
            ],
            "evaluation_criteria": [
                "Severity level",
                "Impact on users",
                "Exploitability",
                "Quality of report",
                "Originality"
            ]
        }