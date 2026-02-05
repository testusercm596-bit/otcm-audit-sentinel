"""
Sentinel Agent - Audit Log Analysis and Anomaly Detection
"""
from typing import List, Dict
from datetime import datetime
import openai
from ..domain.entities import AuditRecord, SecurityFinding, SeverityLevel


class SentinelAgent:
    """
    AI agent for analyzing audit logs and detecting security anomalies
    """
    
    def __init__(self, api_key: str, api_base: str, model: str):
        """
        Initialize Sentinel Agent
        
        Args:
            api_key: API key for the model service
            api_base: Base URL for the API (e.g., Aviator Model endpoint)
            model: Model identifier (e.g., openai/meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8)
        """
        self.client = openai.OpenAI(api_key=api_key, base_url=api_base)
        self.model = model
    
    def analyze_audit_logs(self, audit_records: List[AuditRecord]) -> List[SecurityFinding]:
        """
        Analyze audit logs for security anomalies
        
        Args:
            audit_records: List of audit records to analyze
            
        Returns:
            List of security findings
        """
        findings = []
        
        # Prepare audit data for AI analysis
        audit_summary = self._prepare_audit_summary(audit_records)
        
        # Use AI to detect anomalies
        analysis_result = self._ai_analyze(audit_summary)
        
        # Convert AI results to security findings
        findings = self._parse_ai_results(analysis_result, audit_records)
        
        return findings
    
    def _prepare_audit_summary(self, records: List[AuditRecord]) -> str:
        """Prepare audit records for AI analysis"""
        summary_lines = []
        for record in records:
            line = f"{record.timestamp} | User: {record.user_id} | Action: {record.action} | Doc: {record.document_id}"
            summary_lines.append(line)
        return "\n".join(summary_lines)
    
    def _ai_analyze(self, audit_summary: str) -> Dict:
        """Use AI to analyze audit patterns"""
        prompt = f"""Analyze the following audit logs for security anomalies. 
        Look for:
        - Unusual access patterns
        - Privilege escalation attempts
        - Data exfiltration indicators
        - Suspicious user behavior
        
        Audit Logs:
        {audit_summary}
        
        Provide findings in JSON format with: severity, description, recommendation, confidence_score
        """
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are a security analyst expert at detecting anomalies in audit logs."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        
        import json
        return json.loads(response.choices[0].message.content)
    
    def _parse_ai_results(self, ai_results: Dict, records: List[AuditRecord]) -> List[SecurityFinding]:
        """Convert AI analysis results to SecurityFinding objects"""
        findings = []
        
        # Parse AI results and create SecurityFinding objects
        # This is a placeholder - actual implementation would parse the AI response
        for finding_data in ai_results.get('findings', []):
            finding = SecurityFinding(
                id=None,
                audit_record_id=records[0].id if records else "",
                severity=SeverityLevel[finding_data.get('severity', 'INFO').upper()],
                description=finding_data.get('description', ''),
                recommendation=finding_data.get('recommendation', ''),
                detected_by='sentinel',
                confidence_score=finding_data.get('confidence_score', 0.0),
                created_at=datetime.now()
            )
            findings.append(finding)
        
        return findings
