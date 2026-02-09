"""
Sentinel Agent - Audit Log Analysis and Anomaly Detection
"""
from typing import List, Dict, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict
import openai
import json
import requests
from requests.auth import HTTPBasicAuth
from ..domain.entities import AuditRecord, SecurityFinding, SeverityLevel
from .sentinel import UserProfile


class SentinelAgent:
    """AI agent for audit log analysis with multi-layer detection"""
    
    def __init__(self, api_key: str, api_base: str, model: str, 
                 cm_service_url: Optional[str] = None,
                 cm_username: Optional[str] = None,
                 cm_password: Optional[str] = None,
                 custom_rules: Optional[List[Dict]] = None):
        """Initialize AI sentinel with API credentials and optional admin rules"""
        self.client = openai.OpenAI(api_key=api_key, base_url=api_base)
        self.model = model
        self.custom_rules = custom_rules or []
        self.cm_service_url = cm_service_url
        self.cm_username = cm_username
        self.cm_password = cm_password
        self.cm_enabled = bool(cm_service_url)
        self.fetched_record_ids: Set[str] = set()
        self.last_fetch_time: Optional[datetime] = None
        self.last_processed_record_id: Optional[str] = None
        self.user_profiles: Dict[str, UserProfile] = {}
        self.enhanced_profiling_enabled = True
    
    def set_custom_rules(self, rules: List[Dict]):
        """Update admin rules from sentinel.py (evaluated first during analysis)"""
        self.custom_rules = rules
    
    def fetch_audit_logs_from_service(self, 
                                      since: Optional[datetime] = None,
                                      limit: int = 1000,
                                      user_id: Optional[str] = None,
                                      fetch_all: bool = True) -> List[Dict]:
        """Fetch audit logs from Content Manager History API"""
        if not self.cm_enabled:
            raise RuntimeError("Content Manager service URL not configured")
        if fetch_all and self.last_fetch_time and not since:
            since = self.last_fetch_time
        elif since is None:
            since = datetime.utcnow() - timedelta(hours=1)
        endpoint = f"{self.cm_service_url.rstrip('/')}/History"
        
        params = {
            'q': f'HistoryRecord:{user_id}' if user_id else 'all',
            'pageSize': limit,
            'properties': 'HistoryEventType,HistoryForObjectUri,HistoryLoginLocation,HistoryDoneOn,HistoryEventDescription,HistoryIsSecurityViolation,PossiblyHasSubordinates,HistoryRecord,HistoryLocation,HistoryActivity,HistoryWorkflow,HistoryForObjectType',
            'format': 'json',
            'IncludePropertyDefs': 'true',
            'start': 1,
            'ResultsOnly': 'true'
        }
        auth = HTTPBasicAuth(self.cm_username, self.cm_password) if (self.cm_username and self.cm_password) else None
        
        try:
            response = requests.get(
                endpoint,
                params=params,
                auth=auth,
                timeout=30,
                headers={'Accept': 'application/json'}
            )
            response.raise_for_status()
            
            data = response.json()
            logs = data.get('results', data.get('data', data.get('items', [data] if isinstance(data, dict) else data)))
            new_logs = self._filter_new_logs(logs, since)
            if new_logs:
                self.last_fetch_time = datetime.utcnow()
                if new_logs[0].get('id') or new_logs[0].get('HistoryRecord'):
                    self.last_processed_record_id = new_logs[0].get('id') or new_logs[0].get('HistoryRecord')
            return new_logs
                
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to fetch audit logs from service API: {e}")
    
    def _filter_new_logs(self, logs: List[Dict], since: datetime) -> List[Dict]:
        """Filter out duplicate and old logs"""
        new_logs = []
        for log in logs:
            log_id = log.get('id') or log.get('HistoryRecord') or log.get('log_id')
            if log_id and log_id in self.fetched_record_ids:
                continue
            timestamp_str = log.get('HistoryDoneOn') or log.get('timestamp') or log.get('created_at')
            log_timestamp = self._parse_timestamp(timestamp_str)
            if log_timestamp < since:
                continue
            new_logs.append(log)
            if log_id:
                self.fetched_record_ids.add(log_id)
        return new_logs
    
    def clear_fetch_history(self):
        """Clear fetch history to allow re-fetching"""
        self.fetched_record_ids.clear()
        self.last_fetch_time = None
        self.last_processed_record_id = None
    
    def get_fetch_stats(self) -> Dict:
        """Get fetch statistics"""
        return {
            'total_records_fetched': len(self.fetched_record_ids),
            'last_fetch_time': self.last_fetch_time.isoformat() if self.last_fetch_time else None,
            'last_processed_record_id': self.last_processed_record_id
        }
    
    def fetch_and_analyze(self, 
                          since: Optional[datetime] = None,
                          limit: int = 100,
                          user_id: Optional[str] = None) -> List[SecurityFinding]:
        """Fetch logs from API and analyze for anomalies"""
        raw_logs = self.fetch_audit_logs_from_service(since, limit, user_id)
        audit_records = self._convert_to_audit_records(raw_logs)
        return self.analyze_audit_logs(audit_records)
    
    def _convert_to_audit_records(self, raw_logs: List[Dict]) -> List[AuditRecord]:
        """Convert raw logs to AuditRecord objects"""
        from ..domain.entities import AuditStatus
        records = []
        for log in raw_logs:
            user_id = log.get('HistoryRecord', log.get('user_id', log.get('actor', 'unknown')))
            document_id = log.get('HistoryForObjectUri', log.get('document_id', log.get('record_id', 'unknown')))
            action = log.get('HistoryEventType', log.get('action', log.get('event', 'UNKNOWN')))
            is_security_violation = log.get('HistoryIsSecurityViolation', False)
            status_str = 'FAILED' if is_security_violation else log.get('status', 'COMPLETED')
            status_str = status_str.upper() if isinstance(status_str, str) else 'COMPLETED'
            try:
                status = AuditStatus[status_str] if status_str in AuditStatus.__members__ else AuditStatus.COMPLETED
            except (KeyError, AttributeError):
                status = AuditStatus.COMPLETED
            timestamp_str = log.get('HistoryDoneOn', log.get('timestamp', log.get('created_at')))
            
            record = AuditRecord(
                id=str(log.get('id', log.get('HistoryRecord', ''))),
                document_id=str(document_id),
                timestamp=self._parse_timestamp(timestamp_str),
                user_id=str(user_id),
                action=str(action),
                status=status,
                metadata={
                    **log,
                    'event_description': log.get('HistoryEventDescription'),
                    'location': log.get('HistoryLocation'),
                    'login_location': log.get('HistoryLoginLocation'),
                    'activity': log.get('HistoryActivity'),
                    'workflow': log.get('HistoryWorkflow'),
                    'object_type': log.get('HistoryForObjectType'),
                    'is_security_violation': is_security_violation
                }
            )
            records.append(record)
        
        return records
    
    def _parse_timestamp(self, timestamp_str) -> datetime:
        """Parse timestamp from various formats"""
        if isinstance(timestamp_str, datetime):
            return timestamp_str
        
        if not timestamp_str:
            return datetime.utcnow()
        
        # Try ISO format first
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            pass
        
        # Try common formats
        for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d']:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except (ValueError, TypeError):
                continue
        
        # Default to current time if parsing fails
        return datetime.utcnow()
    
    def train_profiles_from_records(self, audit_records: List[AuditRecord], min_events: int = 20):
        """Train user profiles from historical audit records"""
        user_events = defaultdict(list)
        for record in audit_records:
            user_events[record.user_id].append(self._convert_audit_record_to_event(record))
        for user_id, events in user_events.items():
            if len(events) >= min_events:
                self.train_profile_from_events(user_id, events)
    
    def train_profile_from_events(self, user_id: str, training_events: List[Dict]):
        """Train or update user profile from events"""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = UserProfile(user_id)
        profile = self.user_profiles[user_id]
        for event in training_events:
            self._update_profile_with_event(profile, event)
        self._finalize_profile_training(profile)
    
    def _convert_audit_record_to_event(self, record: AuditRecord) -> Dict:
        """Convert AuditRecord to event dictionary for profile training"""
        metadata = record.metadata or {}
        return {
            'user_id': record.user_id,
            'event_type': record.action,
            'timestamp': record.timestamp.isoformat(),
            'HistoryEventType': {'Value': record.action},
            'HistoryForObjectType': metadata.get('object_type', {}),
            'HistoryDoneOn': {'DateTime': record.timestamp.isoformat()},
            'HistoryLoginLocation': metadata.get('login_location', {}),
            'HistoryIsSecurityViolation': {'Value': metadata.get('is_security_violation', False)},
            'metadata': metadata
        }
    
    def _update_profile_with_event(self, profile: UserProfile, event: Dict):
        """Update profile with single event"""
        profile.total_events += 1
        event_type = event.get('event_type') or event.get('HistoryEventType', {}).get('Value', 'Unknown')
        profile.event_counts[event_type] = profile.event_counts.get(event_type, 0) + 1
        trim_type_obj = event.get('HistoryForObjectType', {})
        if isinstance(trim_type_obj, dict):
            trim_type = trim_type_obj.get('Value') or trim_type_obj.get('StringValue')
        else:
            trim_type = str(trim_type_obj) if trim_type_obj else None
        if trim_type:
            profile.trimtype_access[trim_type] += 1
        timestamp_str = event.get('timestamp') or event.get('HistoryDoneOn', {}).get('DateTime', '')
        if timestamp_str:
            try:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                profile.hours_active[dt.hour] += 1
            except:
                pass
        
        login_location_obj = event.get('HistoryLoginLocation', {})
        if isinstance(login_location_obj, dict):
            login_location = login_location_obj.get('NameString', '')
        else:
            login_location = str(login_location_obj) if login_location_obj else ''
        if login_location:
            profile.login_locations[login_location] += 1
        
        if event.get('HistoryIsSecurityViolation', {}).get('Value', False):
            profile.security_violations += 1
    
    def _finalize_profile_training(self, profile: UserProfile):
        """Calculate final profile statistics after training"""
        # Calculate typical working hours (hours with >10% of activity)
        if profile.hours_active:
            total_hour_events = sum(profile.hours_active.values())
            threshold = total_hour_events * 0.1
            profile.typical_hours = {h for h, count in profile.hours_active.items() if count >= threshold}
    
    def _check_behavioral_anomalies(self, event: Dict, user_id: str) -> List[Dict]:
        """Check for behavioral anomalies"""
        if user_id not in self.user_profiles:
            return []
        profile = self.user_profiles[user_id]
        if profile.total_events < 20:
            return []
        anomalies = []
        
        event_type = event.get('event_type') or event.get('HistoryEventType', {}).get('Value', 'Unknown')
        if event_type not in profile.event_counts and profile.total_events > 50:
            anomalies.append({
                'type': 'new_event_type',
                'severity': 0.6,
                'description': f"New event type '{event_type}'"
            })
        
        trim_type_obj = event.get('HistoryForObjectType', {})
        if isinstance(trim_type_obj, dict):
            trim_type = trim_type_obj.get('Value') or trim_type_obj.get('StringValue')
        else:
            trim_type = str(trim_type_obj) if trim_type_obj else None
        
        if trim_type and trim_type not in profile.trimtype_access and profile.total_events > 50:
            anomalies.append({
                'type': 'new_trimtype',
                'severity': 0.5,
                'description': f"New object type '{trim_type}'"
            })
        
        timestamp_str = event.get('timestamp') or event.get('HistoryDoneOn', {}).get('DateTime', '')
        if timestamp_str and profile.typical_hours:
            try:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                if dt.hour not in profile.typical_hours:
                    anomalies.append({
                        'type': 'unusual_hour',
                        'severity': 0.7,
                        'description': f"Unusual hour {dt.hour}:00"
                    })
            except:
                pass
        
        login_location_obj = event.get('HistoryLoginLocation', {})
        if isinstance(login_location_obj, dict):
            login_location = login_location_obj.get('NameString', '')
        else:
            login_location = str(login_location_obj) if login_location_obj else ''
        
        if login_location and login_location not in profile.login_locations and profile.total_events > 20:
            anomalies.append({
                'type': 'new_location',
                'severity': 0.8,
                'description': f"New location '{login_location}'"
            })
        
        if event_type in profile.event_frequency:
            frequency = profile.event_frequency[event_type]
            if frequency < 0.01 and profile.total_events > 50:
                anomalies.append({
                    'type': 'rare_event',
                    'severity': min(0.95, 0.7 + (1 - frequency) * 0.25),
                    'description': f"Rare event type '{event_type}' (occurs {frequency*100:.1f}% of time)"
                })
        
        event_keywords_high_risk = ['delete', 'remove', 'permission', 'acl', 'access', 'bypass', 'security', 'admin', 'privilege', 'grant', 'revoke']
        event_lower = event_type.lower()
        if any(keyword in event_lower for keyword in event_keywords_high_risk):
            if event_type not in profile.event_counts or profile.event_counts[event_type] < 3:
                anomalies.append({
                    'type': 'sensitive_operation',
                    'severity': 0.85,
                    'description': f"Sensitive operation '{event_type}' (rarely performed)"
                })
        
        if event.get('HistoryIsSecurityViolation', {}).get('Value', False):
            anomalies.append({
                'type': 'security_violation',
                'severity': 0.95,
                'description': "Security violation flag"
            })
        return anomalies
    
    def _check_admin_rules(self, audit_records: List[AuditRecord]) -> List[SecurityFinding]:
        """Validate records against admin rules (highest priority)"""
        findings = []
        if not self.custom_rules:
            return findings
        for record in audit_records:
            event = self._convert_audit_record_to_event(record)
            for rule in self.custom_rules:
                if self._evaluate_admin_rule(rule, event, record):
                    severity_map = {
                        'CRITICAL': SeverityLevel.CRITICAL,
                        'HIGH': SeverityLevel.HIGH,
                        'MEDIUM': SeverityLevel.MEDIUM,
                        'LOW': SeverityLevel.LOW
                    }
                    severity = severity_map.get(rule.get('severity', 'HIGH'), SeverityLevel.HIGHfinding = SecurityFinding(
                        id=None,
                        audit_record_id=record.id,
                        severity=severity,
                        description=f"Admin Rule Violation: {rule.get('description', rule['name'])}",
                        recommendation=f"Immediate review required - admin policy '{rule['name']}' triggered",
                        detected_by='admin_rule_validation',
                        confidence_score=rule.get('risk_score', 0.9),
                        created_at=datetime.now()
                    )
                    findings.append(finding)
        return findings
    
    def _evaluate_admin_rule(self, rule: Dict, event: Dict, record: AuditRecord) -> bool:
        """Evaluate admin rule against event"""
        condition = rule.get('condition')
        operator = rule.get('operator')
        expected_value = rule.get('value')
        
        if condition == 'event_type' or condition == 'action':
            actual_value = record.action
        elif condition == 'hour':
            actual_value = record.timestamp.hour
        elif condition == 'user_id':
            actual_value = record.user_id
        elif condition == 'document_id':
            actual_value = record.document_id
        else:
            actual_value = record.metadata.get(condition)
        if actual_value is None:
            return False
        
        try:
            if operator == '==':
                matches = actual_value == expected_value
            elif operator == '!=':
                matches = actual_value != expected_value
            elif operator == '>':
                matches = actual_value > expected_value
            elif operator == '<':
                matches = actual_value < expected_value
            elif operator == '>=':
                matches = actual_value >= expected_value
            elif operator == '<=':
                matches = actual_value <= expected_value
            elif operator == 'in':
                matches = actual_value in expected_value
            elif operator == 'contains':
                matches = expected_value in str(actual_value)
            else:
                return False
            return matches
        except (TypeError, ValueError):
            return False
    
    def get_user_profile_summary(self, user_id: str) -> Optional[Dict]:
        """Get summary of user's behavioral profile"""
        if user_id not in self.user_profiles:
            return None
        
        profile = self.user_profiles[user_id]
        return {
            'user_id': user_id,
            'total_events': profile.total_events,
            'event_types': dict(profile.event_counts),
            'trimtypes_accessed': dict(profile.trimtype_access),
            'typical_hours': sorted(profile.typical_hours),
            'known_locations': list(profile.login_locations.keys()),
            'security_violations': profile.security_violations,
            'event_frequencies': dict(profile.event_frequency)
        }
    
    def analyze_audit_logs(self, audit_records: List[AuditRecord]) -> List[SecurityFinding]:
        """Analyze logs using admin rules, behavioral profiling, and AI"""
        findings = []
        if self.custom_rules:
            admin_rule_findings = self._check_admin_rules(audit_records)
            findings.extend(admin_rule_findings)
        
        if self.enhanced_profiling_enabled:
            for record in audit_records:
                event = self._convert_audit_record_to_event(record)
                anomalies = self._check_behavioral_anomalies(event, record.user_id)
                for anomaly in anomalies:
                    if anomaly['severity'] >= 0.7:
                        if anomaly['severity'] >= 0.9:
                            severity = SeverityLevel.CRITICAL
                        elif anomaly['severity'] >= 0.7:
                            severity = SeverityLevel.HIGH
                        elif anomaly['severity'] >= 0.5:
                            severity = SeverityLevel.MEDIUM
                        else:
                            severity = SeverityLevel.LOW
                        finding = SecurityFinding(
                            id=None,
                            audit_record_id=record.id,
                            severity=severity,
                            description=f"Behavioral Anomaly: {anomaly['description']}",
                            recommendation="Investigate user activity pattern deviation",
                            detected_by='sentinel_behavioral_analysis',
                            confidence_score=anomaly['severity'],
                            created_at=datetime.now()
                        )
                        findings.append(finding)
        audit_summary = self._prepare_audit_summary(audit_records)
        profile_context = self._prepare_profile_context(audit_records)
        analysis_result = self._ai_analyze(audit_summary, profile_context)
        ai_findings = self._parse_ai_results(analysis_result, audit_records)
        findings.extend(ai_findings)
        return findings
    
    def _prepare_profile_context(self, records: List[AuditRecord]) -> str:
        """Prepare user profile context for AI analysis"""
        if not self.enhanced_profiling_enabled or not self.user_profiles:
            return ""
        users = set(record.user_id for record in records)
        context_lines = ["\n### USER BEHAVIORAL PROFILES"]
        for user_id in users:
            if user_id in self.user_profiles:
                profile = self.user_profiles[user_id]
                context_lines.append(f"\nUser: {user_id}")
                context_lines.append(f"  - Total historical events: {profile.total_events}")
                context_lines.append(f"  - Typical event types: {list(profile.event_counts.keys())[:5]}")
                context_lines.append(f"  - Object types accessed: {list(profile.trimtype_access.keys())[:5]}")
                context_lines.append(f"  - Typical working hours: {sorted(profile.typical_hours) if profile.typical_hours else 'Unknown'}")
                context_lines.append(f"  - Known locations: {list(profile.login_locations.keys())[:3]}")
                context_lines.append(f"  - Security violations: {profile.security_violations}")
                context_lines.append(f"  - Common event frequencies: {dict(list(profile.event_frequency.items())[:5]) if hasattr(profile, 'event_frequency') else 'N/A'}")
        
        return "\n".join(context_lines)
    
    def _prepare_audit_summary(self, records: List[AuditRecord]) -> str:
        """Prepare audit records for AI analysis"""
        summary_lines = []
        for record in records:
            line = f"{record.timestamp} | User: {record.user_id} | Action: {record.action} | Doc: {record.document_id}"
            summary_lines.append(line)
        return "\n".join(summary_lines)
    
    def _ai_analyze(self, audit_summary: str, profile_context: str = "") -> Dict:
        """AI analysis of audit patterns"""
        custom_rules_text = ""
        if self.custom_rules:
            custom_rules_text = "\n\n### ADMIN RULES (PRIORITY)\n"
            for idx, rule in enumerate(self.custom_rules, 1):
                custom_rules_text += f"{idx}. {rule.get('name')}: {rule.get('description')} (Severity: {rule.get('severity', 'HIGH')})\n"
        
        system_prompt = f"""You are Integrity Sentry AI, analyzing OTCM audit logs for security anomalies.
{custom_rules_text}

Evaluate events against:
1. Admin rules (HIGHEST priority - if violated, flag as HIGH_RISK)
2. Behavioral baselines (deviations from user profile)
3. Standard security patterns

Classify as: NORMAL, SUSPICIOUS (needs investigation), or HIGH_RISK (immediate action).

For anomalies, provide precise metrics. Do not infer intent. Prefer false positives over false negatives."""

        user_prompt = f"""Analyze audit events:

{audit_summary}
{profile_context}

Return JSON with findings array:
- severity: CRITICAL/HIGH/MEDIUM/LOW/INFO
- description: Specific anomaly with metrics
- recommendation: Concrete action
- confidence_score: 0-1
- risk_classification: NORMAL/SUSPICIOUS/HIGH_RISK
- anomaly_type: Type

Format: {{"findings": [...]}}"""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"}
        )
        return json.loads(response.choices[0].message.content)
    
    def _parse_ai_results(self, ai_results: Dict, records: List[AuditRecord]) -> List[SecurityFinding]:
        """Convert AI results to SecurityFinding objects"""
        findings = []
        for finding_data in ai_results.get('findings', []):
            severity_map = {
                'CRITICAL': 'CRITICAL',
                'HIGH': 'HIGH',
                'MEDIUM': 'MEDIUM',
                'LOW': 'LOW',
                'INFO': 'INFO'
            }
            severity_str = finding_data.get('severity', 'INFO').upper()
            severity = SeverityLevel[severity_map.get(severity_str, 'INFO')]
            audit_record_id = records[0].id if records else ""
            
            finding = SecurityFinding(
                id=None,
                audit_record_id=audit_record_id,
                severity=severity,
                description=finding_data.get('description', ''),
                recommendation=finding_data.get('recommendation', ''),
                detected_by='sentinel',
                confidence_score=finding_data.get('confidence_score', 0.0),
                created_at=datetime.now()
            )
            findings.append(finding)
        return findings
