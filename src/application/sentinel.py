"""
Sentinel Agent - Rule-based and anomaly detection for audit events
"""
import sys
import os
from typing import List, Dict, Optional
from dataclasses import dataclass
from collections import defaultdict
from datetime import datetime
import math
import openai
import json

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


@dataclass
class SecurityAlert:
    """Security alert with risk score and reason"""
    is_alert: bool
    risk_score: float
    reason: str
    rule_triggered: Optional[str] = None
    distance_score: Optional[float] = None


class UserProfile:
    """User behavioral profile for anomaly detection"""
    def __init__(self, user_id: str, baseline_embedding: Optional[List[float]] = None, 
                 event_counts: Optional[Dict[str, int]] = None):
        self.user_id = user_id
        self.baseline_embedding = baseline_embedding or []
        self.event_counts = event_counts or {}
        self.last_updated = None
        
        # Enhanced profiling attributes
        self.trimtype_access: Dict[str, int] = defaultdict(int)
        self.hours_active: Dict[int, int] = defaultdict(int)
        self.typical_hours: set = set()
        self.login_locations: Dict[str, int] = defaultdict(int)
        self.security_violations: int = 0
        self.total_events: int = 0
        self.event_frequency: Dict[str, float] = {}


class SentinelAgent:
    """Rule-based security event evaluation with NL rule conversion and anomaly detection"""
    
    def __init__(self, rules: List[Dict], user_profiles: Dict[str, UserProfile],
                 api_key: Optional[str] = None, api_base: Optional[str] = None, 
                 model: Optional[str] = None):
        """Initialize Sentinel with rules, user profiles, and optional AI client for NL rule conversion"""
        self.rules = rules
        self.user_profiles = user_profiles
        self.event_history = {}
        self.ai_enabled = api_key and api_base and model
        if self.ai_enabled:
            self.client = openai.OpenAI(api_key=api_key, base_url=api_base)
            self.model = model
        self.distance_threshold_low = 0.5
        self.distance_threshold_medium = 1.0
        self.distance_threshold_high = 2.0
        self.enhanced_profiling_enabled = True
    
    def evaluate_event(self, event: Dict) -> SecurityAlert:
        """Evaluate security event using rules, behavioral profiling, and embedding distance"""
        user_id = self._extract_user_id(event)
        
        rule_alert = self._check_rules(event, user_id)
        if rule_alert:
            return rule_alert
        
        if self.enhanced_profiling_enabled and user_id in self.user_profiles:
            enhanced_alert = self._check_enhanced_anomalies(event, user_id)
            if enhanced_alert:
                return enhanced_alert
        
        if 'embedding' in event and user_id in self.user_profiles:
            profile = self.user_profiles[user_id]
            if profile.baseline_embedding and len(profile.baseline_embedding) > 0:
                anomaly_alert = self._check_anomaly(event, profile)
                if anomaly_alert:
                    return anomaly_alert
        
        return SecurityAlert(
            is_alert=False,
            risk_score=0.0,
            reason="Event appears normal - no rules triggered and within baseline behavior"
        )
    
    def _check_rules(self, event: Dict, user_id: str) -> Optional[SecurityAlert]:
        """Check event against security rules"""
        if user_id not in self.event_history:
            self.event_history[user_id] = {}
        
        event_type = event.get('event_type', event.get('event', 'UNKNOWN'))
        if event_type not in self.event_history[user_id]:
            self.event_history[user_id][event_type] = 0
        self.event_history[user_id][event_type] += 1
        
        for rule in self.rules:
            if self._evaluate_rule(rule, event, user_id):
                return SecurityAlert(
                    is_alert=True,
                    risk_score=rule.get('risk_score', 0.7),
                    reason=rule.get('description', f"Rule '{rule['name']}' triggered"),
                    rule_triggered=rule['name']
                )
        
        return None
    
    def _evaluate_rule(self, rule: Dict, event: Dict, user_id: str) -> bool:
        """Evaluate single rule against event"""
        condition = rule.get('condition')
        operator = rule.get('operator')
        expected_value = rule.get('value')
        threshold = rule.get('threshold')
        
        if condition == 'event_type':
            actual_value = event.get('event_type', event.get('event'))
        elif condition == 'hour':
            timestamp = event.get('timestamp', '')
            if isinstance(timestamp, str) and 'T' in timestamp:
                time_part = timestamp.split('T')[1]
                actual_value = int(time_part.split(':')[0])
            else:
                return False
        else:
            actual_value = event.get(condition)
        
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
        else:
            return False
        
        if threshold is not None and matches:
            event_count = self.event_history[user_id].get(actual_value, 0)
            return event_count > threshold
        
        return matches
    
    def _check_anomaly(self, event: Dict, profile: UserProfile) -> Optional[SecurityAlert]:
        """Check for anomalies using embedding distance"""
        event_embedding = event.get('embedding', [])
        baseline_embedding = profile.baseline_embedding
        
        if not event_embedding or not baseline_embedding:
            return None
        
        distance = self._euclidean_distance(event_embedding, baseline_embedding)
        
        if distance > self.distance_threshold_high:
            return SecurityAlert(
                is_alert=True,
                risk_score=0.9,
                reason=f"High anomaly detected: Event significantly deviates from user baseline (distance: {distance:.2f})",
                distance_score=distance
            )
        elif distance > self.distance_threshold_medium:
            return SecurityAlert(
                is_alert=True,
                risk_score=0.7,
                reason=f"Moderate anomaly detected: Event deviates from user baseline (distance: {distance:.2f})",
                distance_score=distance
            )
        elif distance > self.distance_threshold_low:
            return SecurityAlert(
                is_alert=True,
                risk_score=0.4,
                reason=f"Low anomaly detected: Event slightly deviates from baseline (distance: {distance:.2f})",
                distance_score=distance
            )
        
        return None
    
    @staticmethod
    def _euclidean_distance(vec1: List[float], vec2: List[float]) -> float:
        """Calculate Euclidean distance between two vectors"""
        if len(vec1) != len(vec2):
            raise ValueError(f"Vectors must have same length: {len(vec1)} != {len(vec2)}")
        
        sum_squares = sum((a - b) ** 2 for a, b in zip(vec1, vec2))
        return math.sqrt(sum_squares)
    
    def reset_event_history(self, user_id: Optional[str] = None):
        """Reset event history for user or all users"""
        if user_id:
            self.event_history[user_id] = {}
        else:
            self.event_history = {}
    
    def add_rule(self, rule: Dict):
        """Add a new rule to the agent"""
        self.rules.append(rule)
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove rule by name"""
        initial_count = len(self.rules)
        self.rules = [r for r in self.rules if r.get('name') != rule_name]
        return len(self.rules) < initial_count
    
    def remove_rule_by_index(self, index: int) -> bool:
        """Remove rule by index"""
        if 0 <= index < len(self.rules):
            self.rules.pop(index)
            return True
        return False
    
    def clear_all_rules(self) -> int:
        """Remove all rules and return count"""
        count = len(self.rules)
        self.rules = []
        return count
    
    def get_user_profile(self, user_id: str) -> Optional[UserProfile]:
        """Get user profile by ID"""
        return self.user_profiles.get(user_id)
    
    def update_user_profile(self, user_id: str, profile: UserProfile):
        """Update or add a user profile"""
        self.user_profiles[user_id] = profile
    
    def _extract_user_id(self, event: Dict) -> str:
        """Extract user ID from event"""
        if 'user_id' in event:
            return event['user_id']
        description = event.get('HistoryEventDescription', {}).get('Value', '')
        if "done by '" in description:
            start = description.index("done by '") + len("done by '")
            end = description.index("'", start)
            user_id = description[start:end]
            if '\\' in user_id:
                user_id = user_id.split('\\')[1]
            return user_id
        login_location = event.get('HistoryLoginLocation', {}).get('NameString', '')
        return login_location if login_location else 'unknown'
    
    def train_profile_from_events(self, user_id: str, training_events: List[Dict]):
        """Train or update user profile from historical events"""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = UserProfile(user_id)
        profile = self.user_profiles[user_id]
        for event in training_events:
            self._update_profile_with_event(profile, event)
        self._finalize_profile_training(profile)
    
    def _update_profile_with_event(self, profile: UserProfile, event: Dict):
        """Update profile with single event"""
        profile.total_events += 1
        event_type = event.get('event_type') or event.get('HistoryEventType', {}).get('Value', 'Unknown')
        profile.event_counts[event_type] = profile.event_counts.get(event_type, 0) + 1
        trim_type = event.get('HistoryForObjectType', {}).get('Value')
        if trim_type:
            profile.trimtype_access[trim_type] += 1
        
        timestamp_str = event.get('timestamp') or event.get('HistoryDoneOn', {}).get('DateTime', '')
        if timestamp_str:
            try:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                profile.hours_active[dt.hour] += 1
            except:
                pass
        login_location = event.get('HistoryLoginLocation', {}).get('NameString', '')
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
    
    def _check_enhanced_anomalies(self, event: Dict, user_id: str) -> Optional[SecurityAlert]:
        """Check for behavioral anomalies"""
        profile = self.user_profiles[user_id]
        if profile.total_events < 20:
            return None
        
        anomalies = []
        max_severity = 0.0
        
        event_type = event.get('event_type') or event.get('HistoryEventType', {}).get('Value', 'Unknown')
        if event_type not in profile.event_counts and profile.total_events > 50:
            anomalies.append(f"New event type '{event_type}'")
            max_severity = max(max_severity, 0.6)
        trim_type = event.get('HistoryForObjectType', {}).get('Value')
        if trim_type and trim_type not in profile.trimtype_access and profile.total_events > 50:
            anomalies.append(f"New object type '{trim_type}'")
            max_severity = max(max_severity, 0.5)
        
        timestamp_str = event.get('timestamp') or event.get('HistoryDoneOn', {}).get('DateTime', '')
        if timestamp_str and profile.typical_hours:
            try:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                if dt.hour not in profile.typical_hours:
                    anomalies.append(f"Unusual hour {dt.hour}:00")
                    max_severity = max(max_severity, 0.7)
            except:
                pass
        
        login_location = event.get('HistoryLoginLocation', {}).get('NameString', '')
        if login_location and login_location not in profile.login_locations and profile.total_events > 20:
            anomalies.append(f"New location '{login_location}'")
            max_severity = max(max_severity, 0.8)
        
        if event_type in profile.event_frequency:
            frequency = profile.event_frequency[event_type]
            if frequency < 0.01 and profile.total_events > 50:
                anomalies.append(f"Rare event type '{event_type}' (occurs {frequency*100:.1f}% of time)")
                severity = min(0.95, 0.7 + (1 - frequency) * 0.25)
                max_severity = max(max_severity, severity)
        
        event_keywords_high_risk = ['delete', 'remove', 'permission', 'acl', 'access', 'bypass', 'security', 'admin', 'privilege', 'grant', 'revoke']
        event_lower = event_type.lower()
        if any(keyword in event_lower for keyword in event_keywords_high_risk):
            if event_type not in profile.event_counts or profile.event_counts[event_type] < 3:
                anomalies.append(f"Sensitive operation '{event_type}' (rarely performed)")
                max_severity = max(max_severity, 0.85)
        
        if event.get('HistoryIsSecurityViolation', {}).get('Value', False):
            anomalies.append("Security violation flag set")
            max_severity = max(max_severity, 0.95)
        
        if anomalies:
            reason = f"User '{user_id}' behavioral anomalies detected:\n" + "\n".join(f"  • {a}" for a in anomalies)
            return SecurityAlert(
                is_alert=True,
                risk_score=max_severity,
                reason=reason,
                rule_triggered="Enhanced Behavioral Analysis"
            )
        
        return None
    
    def add_rule_from_natural_language(self, natural_language_rule: str) -> Dict:
        """Convert natural language rule to structured format using AI"""
        if not self.ai_enabled:
            raise RuntimeError("AI is not enabled. Provide api_key, api_base, and model to use natural language rules.")
        
        conversion_prompt = f"""Convert this security rule to JSON:
"{natural_language_rule}"

JSON fields: name, condition, operator, value, threshold (optional), time_window (optional), risk_score (0-1), description, severity (CRITICAL/HIGH/MEDIUM/LOW).

Examples:
"Delete >10 files in 1 hour" → {{"name":"Excessive Deletes","condition":"event_type","operator":"==","value":"DELETE","threshold":10,"time_window":60,"risk_score":0.8,"description":"User deleted >10 files in 1 hour","severity":"HIGH"}}
"Access after 6pm" → {{"name":"After Hours Access","condition":"hour","operator":">=","value":18,"risk_score":0.7,"description":"Access after 6pm","severity":"MEDIUM"}}

Return JSON only, no explanation."""

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "Convert security rules to JSON. Return only valid JSON."},
                {"role": "user", "content": conversion_prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.3
        )
        rule = json.loads(response.choices[0].message.content)
        self.rules.append(rule)
        return rule
    
    def get_rules(self) -> List[Dict]:
        """Get all active rules"""
        return self.rules.copy()
    
    def get_rule_summary(self) -> List[Dict]:
        """Get summary of all rules"""
        summaries = []
        for idx, rule in enumerate(self.rules):
            summaries.append({
                'index': idx,
                'name': rule.get('name', 'Unnamed Rule'),
                'severity': rule.get('severity', 'MEDIUM'),
                'risk_score': rule.get('risk_score', 0.5),
                'description': rule.get('description', 'No description'),
                'condition': rule.get('condition', 'unknown'),
                'value': rule.get('value', 'unknown')
            })
        return summaries
    
    def find_rules_by_name(self, search_term: str) -> List[Dict]:
        """Find rules by name (case-insensitive)"""
        search_lower = search_term.lower()
        return [r for r in self.rules if search_lower in r.get('name', '').lower()]
    
    def import_rules_from_list(self, natural_language_rules: List[str]) -> List[Dict]:
        """Convert multiple NL rules at once"""
        converted_rules = []
        for nl_rule in natural_language_rules:
            try:
                rule = self.add_rule_from_natural_language(nl_rule)
                converted_rules.append(rule)
            except Exception as e:
                pass
        return converted_rules
    
    def export_rules_for_ai_agent(self) -> List[Dict]:
        """Export rules for AI agent"""
        return self.get_rules()
    
    def sync_rules_to_ai_agent(self, sentinel_agent):
        """Sync admin rules to AI sentinel agent"""
        rules = self.export_rules_for_ai_agent()
        sentinel_agent.set_custom_rules(rules)
        """
        Synchronize admin rules to sentinel_agent for AI-based detection
        
        Args:
            sentinel_agent: Instance of SentinelAgent from sentinel_agent.py
            
        Usage:
            # Admin defines rules in natural language
            sentinel.add_rule_from_natural_language(
                "Alert if user deletes more than 5 records in 10 minutes"
            )
            
            # Sync rules to AI agent
            sentinel.sync_rules_to_ai_agent(ai_sentinel_agent)
            
            # Now AI agent will respect admin rules in analysis
        """
        rules = self.export_rules_for_ai_agent()
        sentinel_agent.set_custom_rules(rules)
        print(f"✓ Synced {len(rules)} admin rule(s) to AI sentinel agent")
