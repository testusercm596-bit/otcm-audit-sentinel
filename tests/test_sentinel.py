"""
Unit tests for Sentinel Agent
"""
import pytest
from src.application.sentinel import SentinelAgent, SecurityAlert, UserProfile


class TestSentinelAgent:
    """Test suite for Sentinel Agent"""
    
    @pytest.fixture
    def sample_rules(self):
        """Create sample security rules"""
        return [
            {
                'name': 'Excessive Deletes',
                'condition': 'event_type',
                'operator': '==',
                'value': 'DELETE',
                'threshold': 5,
                'risk_score': 0.8,
                'description': 'User performed more than 5 delete operations'
            },
            {
                'name': 'Admin Access',
                'condition': 'event_type',
                'operator': '==',
                'value': 'ADMIN_ACCESS',
                'threshold': None,
                'risk_score': 0.9,
                'description': 'Unauthorized admin access attempt'
            }
        ]
    
    @pytest.fixture
    def sample_user_profile(self):
        """Create sample user profile with baseline"""
        # Simple 3D vector for testing
        baseline = [0.5, 0.5, 0.5]
        return UserProfile(
            user_id="john.doe",
            baseline_embedding=baseline,
            event_counts={'READ': 100, 'WRITE': 50}
        )
    
    @pytest.fixture
    def sentinel_agent(self, sample_rules, sample_user_profile):
        """Create Sentinel Agent instance"""
        user_profiles = {"john.doe": sample_user_profile}
        return SentinelAgent(rules=sample_rules, user_profiles=user_profiles)
    
    def test_agent_initialization(self, sentinel_agent):
        """Test agent initialization"""
        assert len(sentinel_agent.rules) == 2
        assert "john.doe" in sentinel_agent.user_profiles
    
    def test_no_alert_normal_event(self, sentinel_agent):
        """Test normal event doesn't trigger alert"""
        event = {
            'user_id': 'john.doe',
            'event_type': 'READ',
            'timestamp': '2026-02-05T10:00:00',
            'embedding': [0.5, 0.5, 0.5]  # Same as baseline
        }
        
        alert = sentinel_agent.evaluate_event(event)
        
        assert isinstance(alert, SecurityAlert)
        assert alert.is_alert is False
        assert alert.risk_score == 0.0
    
    def test_rule_based_alert_admin_access(self, sentinel_agent):
        """Test rule-based detection for admin access"""
        event = {
            'user_id': 'john.doe',
            'event_type': 'ADMIN_ACCESS',
            'timestamp': '2026-02-05T10:00:00'
        }
        
        alert = sentinel_agent.evaluate_event(event)
        
        assert alert.is_alert is True
        assert alert.risk_score == 0.9
        assert alert.rule_triggered == 'Admin Access'
        assert 'admin' in alert.reason.lower()
    
    def test_rule_based_alert_excessive_deletes(self, sentinel_agent):
        """Test rule-based detection for excessive deletes"""
        # Generate 6 DELETE events to exceed threshold of 5
        for i in range(6):
            event = {
                'user_id': 'jane.smith',
                'event_type': 'DELETE',
                'timestamp': f'2026-02-05T10:{i:02d}:00'
            }
            alert = sentinel_agent.evaluate_event(event)
            
            if i < 5:
                # First 5 should not trigger
                assert alert.is_alert is False
            else:
                # 6th should trigger
                assert alert.is_alert is True
                assert alert.risk_score == 0.8
                assert alert.rule_triggered == 'Excessive Deletes'
    
    def test_anomaly_detection_high(self, sentinel_agent):
        """Test anomaly detection with high deviation"""
        # Event with embedding far from baseline [0.5, 0.5, 0.5]
        event = {
            'user_id': 'john.doe',
            'event_type': 'READ',
            'timestamp': '2026-02-05T10:00:00',
            'embedding': [5.0, 5.0, 5.0]  # Very different from baseline
        }
        
        alert = sentinel_agent.evaluate_event(event)
        
        assert alert.is_alert is True
        assert alert.risk_score >= 0.7  # Should be high risk
        assert alert.distance_score is not None
        assert alert.distance_score > 0
        assert 'anomaly' in alert.reason.lower()
    
    def test_anomaly_detection_medium(self, sentinel_agent):
        """Test anomaly detection with medium deviation"""
        event = {
            'user_id': 'john.doe',
            'event_type': 'READ',
            'timestamp': '2026-02-05T10:00:00',
            'embedding': [1.5, 1.5, 1.5]  # Moderately different
        }
        
        alert = sentinel_agent.evaluate_event(event)
        
        assert alert.is_alert is True
        assert 0.4 <= alert.risk_score <= 0.9
        assert alert.distance_score is not None
    
    def test_euclidean_distance_calculation(self):
        """Test Euclidean distance calculation"""
        vec1 = [0.0, 0.0, 0.0]
        vec2 = [3.0, 4.0, 0.0]
        
        distance = SentinelAgent._euclidean_distance(vec1, vec2)
        
        assert distance == 5.0  # 3-4-5 triangle
    
    def test_euclidean_distance_same_vectors(self):
        """Test Euclidean distance of identical vectors"""
        vec1 = [1.0, 2.0, 3.0]
        vec2 = [1.0, 2.0, 3.0]
        
        distance = SentinelAgent._euclidean_distance(vec1, vec2)
        
        assert distance == 0.0
    
    def test_euclidean_distance_different_lengths(self):
        """Test Euclidean distance with mismatched vector lengths"""
        vec1 = [1.0, 2.0]
        vec2 = [1.0, 2.0, 3.0]
        
        with pytest.raises(ValueError):
            SentinelAgent._euclidean_distance(vec1, vec2)
    
    def test_reset_event_history_single_user(self, sentinel_agent):
        """Test resetting event history for a single user"""
        # Generate some events
        event = {
            'user_id': 'john.doe',
            'event_type': 'DELETE',
            'timestamp': '2026-02-05T10:00:00'
        }
        sentinel_agent.evaluate_event(event)
        
        assert 'john.doe' in sentinel_agent.event_history
        
        # Reset
        sentinel_agent.reset_event_history('john.doe')
        
        assert sentinel_agent.event_history['john.doe'] == {}
    
    def test_reset_event_history_all_users(self, sentinel_agent):
        """Test resetting all event history"""
        # Generate events for multiple users
        for user in ['john.doe', 'jane.smith']:
            event = {
                'user_id': user,
                'event_type': 'READ',
                'timestamp': '2026-02-05T10:00:00'
            }
            sentinel_agent.evaluate_event(event)
        
        # Reset all
        sentinel_agent.reset_event_history()
        
        assert sentinel_agent.event_history == {}
    
    def test_add_rule(self, sentinel_agent):
        """Test adding a new rule"""
        new_rule = {
            'name': 'Test Rule',
            'condition': 'event_type',
            'operator': '==',
            'value': 'TEST',
            'risk_score': 0.5
        }
        
        initial_count = len(sentinel_agent.rules)
        sentinel_agent.add_rule(new_rule)
        
        assert len(sentinel_agent.rules) == initial_count + 1
        assert new_rule in sentinel_agent.rules
    
    def test_remove_rule(self, sentinel_agent):
        """Test removing a rule"""
        initial_count = len(sentinel_agent.rules)
        sentinel_agent.remove_rule('Excessive Deletes')
        
        assert len(sentinel_agent.rules) == initial_count - 1
        assert not any(r['name'] == 'Excessive Deletes' for r in sentinel_agent.rules)
    
    def test_get_user_profile(self, sentinel_agent):
        """Test getting user profile"""
        profile = sentinel_agent.get_user_profile('john.doe')
        
        assert profile is not None
        assert profile.user_id == 'john.doe'
        assert len(profile.baseline_embedding) == 3
    
    def test_update_user_profile(self, sentinel_agent):
        """Test updating user profile"""
        new_profile = UserProfile(
            user_id='new.user',
            baseline_embedding=[1.0, 1.0, 1.0]
        )
        
        sentinel_agent.update_user_profile('new.user', new_profile)
        
        assert 'new.user' in sentinel_agent.user_profiles
        assert sentinel_agent.user_profiles['new.user'].baseline_embedding == [1.0, 1.0, 1.0]
    
    def test_event_without_embedding(self, sentinel_agent):
        """Test event evaluation without embedding"""
        event = {
            'user_id': 'john.doe',
            'event_type': 'READ',
            'timestamp': '2026-02-05T10:00:00'
            # No embedding
        }
        
        alert = sentinel_agent.evaluate_event(event)
        
        # Should only check rules, not anomaly detection
        assert isinstance(alert, SecurityAlert)
