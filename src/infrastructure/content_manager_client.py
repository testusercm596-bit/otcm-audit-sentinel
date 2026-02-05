"""
OpenText Content Manager API Client
"""
import requests
from requests_ntlm import HttpNtlmAuth
from typing import List, Dict, Optional
from datetime import datetime


class ContentManagerClient:
    """Client for interacting with OpenText Content Manager API with NTLM authentication"""
    
    def __init__(self, base_url: str, username: str, password: str, domain: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.session = requests.Session()
        
        # Setup NTLM authentication
        if domain:
            auth_username = f"{domain}\\{username}"
        else:
            auth_username = username
            
        self.session.auth = HttpNtlmAuth(auth_username, password)
        self.session.headers.update({
            'Content-Type': 'application/json'
        })
    
    def get_audit_logs(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Retrieve audit logs from Content Manager"""
        endpoint = f"{self.base_url}/api/v2/audit-logs"
        params = {
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat()
        }
        
        response = self.session.get(endpoint, params=params)
        response.raise_for_status()
        return response.json().get('data', [])
    
    def get_document(self, document_id: str) -> Dict:
        """Retrieve a specific document"""
        endpoint = f"{self.base_url}/api/v2/documents/{document_id}"
        response = self.session.get(endpoint)
        response.raise_for_status()
        return response.json()
    
    def get_permissions(self, document_id: str) -> List[Dict]:
        """Get document permissions"""
        endpoint = f"{self.base_url}/api/v2/documents/{document_id}/permissions"
        response = self.session.get(endpoint)
        response.raise_for_status()
        return response.json().get('permissions', [])
    
    def search_documents(self, query: str, filters: Optional[Dict] = None) -> List[Dict]:
        """Search for documents"""
        endpoint = f"{self.base_url}/api/v2/search"
        payload = {'query': query}
        if filters:
            payload['filters'] = filters
        
        response = self.session.post(endpoint, json=payload)
        response.raise_for_status()
        return response.json().get('results', [])
