"""
Unit tests for Hallucinator Agent
"""
import pytest
import json
from src.application.hallucinator import HallucinatorAgent, DefenseContext


class TestHallucinatorAgent:
    """Test suite for Hallucinator Agent"""
    
    @pytest.fixture
    def hallucinator_agent(self):
        """Create Hallucinator Agent instance"""
        return HallucinatorAgent(model="gpt-4", temperature=0.7)
    
    @pytest.fixture
    def sample_alert(self):
        """Create sample security alert"""
        return {
            'is_alert': True,
            'risk_score': 0.8,
            'reason': 'User performed more than 5 delete operations',
            'event': {
                'user_id': 'john.doe',
                'event_type': 'DELETE',
                'timestamp': '2026-02-05T16:30:00',
                'record_type': 'Document',
                'record_title': 'Q4_Report.pdf'
            }
        }
    
    @pytest.fixture
    def sample_user_history(self):
        """Create sample user history"""
        return [
            {
                'event_type': 'READ',
                'timestamp': '2026-02-05T09:00:00',
                'record_type': 'Document'
            },
            {
                'event_type': 'WRITE',
                'timestamp': '2026-02-05T10:30:00',
                'record_type': 'Document'
            },
            {
                'event_type': 'DELETE',
                'timestamp': '2026-02-05T16:00:00',
                'record_type': 'Document'
            }
        ]
    
    def test_agent_initialization(self, hallucinator_agent):
        """Test agent initialization"""
        assert hallucinator_agent.model == "gpt-4"
        assert hallucinator_agent.temperature == 0.7
    
    def test_generate_defense(self, hallucinator_agent, sample_alert, sample_user_history):
        """Test defense generation"""
        defense = hallucinator_agent.generate_defense(sample_alert, sample_user_history)
        
        assert isinstance(defense, DefenseContext)
        assert isinstance(defense.justification, str)
        assert len(defense.justification) > 0
        assert 0.0 <= defense.confidence <= 1.0
    
    def test_defense_context_structure(self, hallucinator_agent, sample_alert, sample_user_history):
        """Test DefenseContext has required fields"""
        defense = hallucinator_agent.generate_defense(sample_alert, sample_user_history)
        
        assert hasattr(defense, 'justification')
        assert hasattr(defense, 'confidence')
        assert hasattr(defense, 'supporting_evidence')
        assert hasattr(defense, 'risk_mitigation')
    
    def test_format_user_history(self, hallucinator_agent, sample_user_history):
        """Test user history formatting"""
        formatted = hallucinator_agent._format_user_history(sample_user_history)
        
        assert isinstance(formatted, str)
        assert 'READ' in formatted
        assert 'WRITE' in formatted
        assert 'DELETE' in formatted
    
    def test_format_user_history_empty(self, hallucinator_agent):
        """Test formatting empty user history"""
        formatted = hallucinator_agent._format_user_history([])
        
        assert isinstance(formatted, str)
        assert 'No historical data' in formatted
    
    def test_format_event(self, hallucinator_agent, sample_alert):
        """Test event formatting"""
        event = sample_alert['event']
        formatted = hallucinator_agent._format_event(event)
        
        assert isinstance(formatted, str)
        assert 'john.doe' in formatted
        assert 'DELETE' in formatted
    
    def test_format_event_empty(self, hallucinator_agent):
        """Test formatting empty event"""
        formatted = hallucinator_agent._format_event({})
        
        assert isinstance(formatted, str)
        assert 'No event details' in formatted
    
    def test_construct_defense_prompt(self, hallucinator_agent, sample_alert, sample_user_history):
        """Test defense prompt construction"""
        prompt = hallucinator_agent._construct_defense_prompt(sample_alert, sample_user_history)
        
        assert isinstance(prompt, str)
        assert 'Defense Attorney' in prompt
        assert 'benign' in prompt.lower()
        assert 'justification' in prompt.lower()
        assert str(sample_alert['risk_score']) in prompt
    
    def test_call_llm_returns_json(self, hallucinator_agent):
        """Test LLM call returns valid JSON"""
        prompt = "Test prompt"
        response = hallucinator_agent._call_llm(prompt)
        
        # Should be valid JSON
        data = json.loads(response)
        assert 'justification' in data
        assert 'confidence' in data
    
    def test_parse_llm_response_valid_json(self, hallucinator_agent):
        """Test parsing valid LLM response"""
        llm_response = json.dumps({
            'justification': 'User was performing routine cleanup',
            'confidence': 0.75,
            'supporting_evidence': ['Evidence 1', 'Evidence 2'],
            'risk_mitigation': 'Monitor for 24 hours'
        })
        
        defense = hallucinator_agent._parse_llm_response(llm_response)
        
        assert defense.justification == 'User was performing routine cleanup'
        assert defense.confidence == 0.75
        assert len(defense.supporting_evidence) == 2
        assert 'Monitor' in defense.risk_mitigation
    
    def test_parse_llm_response_invalid_json(self, hallucinator_agent):
        """Test parsing invalid JSON response"""
        llm_response = "This is not valid JSON"
        
        defense = hallucinator_agent._parse_llm_response(llm_response)
        
        assert 'Error' in defense.justification
        assert defense.confidence == 0.0
    
    def test_delete_alert_defense(self, hallucinator_agent):
        """Test defense for delete alert"""
        alert = {
            'is_alert': True,
            'risk_score': 0.8,
            'reason': 'User performed more than 5 delete operations',
            'event': {
                'user_id': 'john.doe',
                'event_type': 'DELETE',
                'timestamp': '2026-02-05T16:30:00'
            }
        }
        
        defense = hallucinator_agent.generate_defense(alert, [])
        
        assert defense.confidence > 0.5  # Should find reasonable defense
        assert 'cleanup' in defense.justification.lower() or 'retention' in defense.justification.lower()
    
    def test_admin_alert_low_confidence(self, hallucinator_agent):
        """Test that admin alerts get low confidence defenses"""
        alert = {
            'is_alert': True,
            'risk_score': 0.95,
            'reason': 'Unauthorized admin access',
            'event': {
                'user_id': 'john.doe',
                'event_type': 'ADMIN_ACCESS',
                'timestamp': '2026-02-05T22:00:00'
            }
        }
        
        defense = hallucinator_agent.generate_defense(alert, [])
        
        assert defense.confidence < 0.3  # Should have low confidence
    
    def test_batch_generate_defenses(self, hallucinator_agent, sample_alert):
        """Test batch defense generation"""
        alerts = [sample_alert, sample_alert.copy()]
        user_history = {
            'john.doe': [
                {'event_type': 'READ', 'timestamp': '2026-02-05T09:00:00'}
            ]
        }
        
        defenses = hallucinator_agent.batch_generate_defenses(alerts, user_history)
        
        assert len(defenses) == 2
        assert all(isinstance(d, DefenseContext) for d in defenses)
    
    def test_should_dismiss_alert_high_confidence(self, hallucinator_agent):
        """Test alert dismissal with high confidence defense"""
        defense = DefenseContext(
            justification="Legitimate business activity",
            confidence=0.85,
            supporting_evidence=["Evidence"],
            risk_mitigation="None needed"
        )
        
        should_dismiss = hallucinator_agent.should_dismiss_alert(defense, confidence_threshold=0.7)
        
        assert should_dismiss is True
    
    def test_should_dismiss_alert_low_confidence(self, hallucinator_agent):
        """Test alert not dismissed with low confidence defense"""
        defense = DefenseContext(
            justification="Cannot find benign explanation",
            confidence=0.3,
            supporting_evidence=[],
            risk_mitigation="Investigate immediately"
        )
        
        should_dismiss = hallucinator_agent.should_dismiss_alert(defense, confidence_threshold=0.7)
        
        assert should_dismiss is False
    
    def test_custom_confidence_threshold(self, hallucinator_agent):
        """Test custom confidence threshold"""
        defense = DefenseContext(
            justification="Possible legitimate activity",
            confidence=0.6
        )
        
        # Should not dismiss with high threshold
        assert hallucinator_agent.should_dismiss_alert(defense, confidence_threshold=0.7) is False
        
        # Should dismiss with low threshold
        assert hallucinator_agent.should_dismiss_alert(defense, confidence_threshold=0.5) is True
