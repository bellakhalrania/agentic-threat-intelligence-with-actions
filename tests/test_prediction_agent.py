"""
Unit tests for the Prediction Agent.

Tests the prediction agent's ability to:
- Predict likely next techniques based on observed techniques
- Validate predicted technique IDs against the knowledge base
- Handle edge cases (empty techniques, no RAG context, etc.)
"""

import pytest
from unittest.mock import patch, MagicMock
from agents.prediction_agent import PredictionAgent


class TestPredictionAgent:
    """Test suite for PredictionAgent"""

    def test_run_with_empty_techniques(self):
        """Test that agent returns early when no techniques are observed"""
        agent = PredictionAgent()
        result = agent.run([], {"campaign_id": "test-campaign"})
        
        assert result["likely_next_techniques"] == []
        assert "No techniques observed yet" in result["rationale"]

    @patch('agents.prediction_agent.retrieve_likely_next_techniques_with_ids')
    @patch('agents.prediction_agent.invoke_llm')
    def test_run_with_techniques_and_rag_context(self, mock_llm, mock_rag):
        """Test successful prediction with RAG context and LLM response"""
        # Mock RAG to return context and candidate IDs
        mock_rag.return_value = (
            "After T1059.001 PowerShell, attackers commonly use T1105 Ingress Tool Transfer",
            {"T1105", "T1055", "T1566"}
        )
        
        # Mock LLM to return valid predictions
        mock_llm.return_value = '''
        {
            "likely_next_techniques": [
                {"technique_id": "T1105", "name": "Ingress Tool Transfer"},
                {"technique_id": "T1055", "name": "Process Injection"}
            ],
            "rationale": "Based on observed PowerShell execution, attackers typically download tools and inject processes."
        }
        '''
        
        agent = PredictionAgent()
        techniques = [
            {"technique_id": "T1059.001", "technique_name": "PowerShell", "confidence": 0.9}
        ]
        campaign = {"campaign_id": "test-campaign", "threat_level": "high"}
        
        result = agent.run(techniques, campaign)
        
        assert len(result["likely_next_techniques"]) == 2
        assert result["rationale"] is not None
        mock_rag.assert_called_once()
        mock_llm.assert_called_once()

    @patch('agents.prediction_agent.retrieve_likely_next_techniques_with_ids')
    def test_run_with_no_rag_context(self, mock_rag):
        """Test that agent skips prediction when RAG returns no context"""
        # Mock RAG to return empty context
        mock_rag.return_value = ("", set())
        
        agent = PredictionAgent()
        techniques = [
            {"technique_id": "T1059.001", "technique_name": "PowerShell"}
        ]
        campaign = {"campaign_id": "test-campaign"}
        
        result = agent.run(techniques, campaign)
        
        assert result["likely_next_techniques"] == []
        assert "Prediction skipped" in result["rationale"]
        # LLM should not be called when RAG returns nothing
        mock_rag.assert_called_once()

    @patch('agents.prediction_agent.retrieve_likely_next_techniques_with_ids')
    @patch('agents.prediction_agent.invoke_llm')
    def test_validation_removes_invalid_technique_ids(self, mock_llm, mock_rag):
        """Test that validation removes technique IDs not in candidate set"""
        # Mock RAG to return specific candidate IDs
        mock_rag.return_value = (
            "Related techniques context",
            {"T1105", "T1055"}  # Only these are valid
        )
        
        # Mock LLM to return predictions including invalid IDs
        mock_llm.return_value = '''
        {
            "likely_next_techniques": [
                {"technique_id": "T1105", "name": "Ingress Tool Transfer"},
                {"technique_id": "T9999", "name": "Fake Technique"},
                {"technique_id": "T1055", "name": "Process Injection"}
            ],
            "rationale": "Test with invalid technique ID"
        }
        '''
        
        agent = PredictionAgent()
        techniques = [{"technique_id": "T1059.001", "technique_name": "PowerShell"}]
        campaign = {"campaign_id": "test-campaign"}
        
        result = agent.run(techniques, campaign)
        
        # Only valid technique IDs should remain
        assert len(result["likely_next_techniques"]) == 2
        technique_ids = [t.get("technique_id") for t in result["likely_next_techniques"]]
        assert "T1105" in technique_ids
        assert "T1055" in technique_ids
        assert "T9999" not in technique_ids

    @patch('knowledge.attack.service.AttackService')
    @patch('agents.prediction_agent.retrieve_likely_next_techniques_with_ids')
    @patch('agents.prediction_agent.invoke_llm')
    def test_validation_removes_deprecated_techniques(self, mock_invoke_llm, mock_rag, mock_attack_service):
        """Test that validation removes deprecated techniques not in knowledge base"""
        # Mock RAG to return candidate IDs
        mock_rag.return_value = (
            "Related techniques context",
            {"T1105", "T1060"}  # T1060 might be deprecated
        )
        
        # Mock LLM to return predictions
        mock_invoke_llm.return_value = '''
        {
            "likely_next_techniques": [
                {"technique_id": "T1105", "name": "Ingress Tool Transfer"},
                {"technique_id": "T1060", "name": "Registry Run Keys / Startup Folder"}
            ],
            "rationale": "Test with deprecated technique"
        }
        '''
        
        # Mock AttackService to raise RecordNotFoundError for T1060 (deprecated)
        mock_service_instance = MagicMock()
        mock_attack_service.create.return_value = mock_service_instance
        
        def get_technique_side_effect(tech_id):
            if tech_id == "T1060":
                from knowledge.base.exceptions import RecordNotFoundError
                raise RecordNotFoundError(f"Technique {tech_id} not found")
            return {"attack_id": tech_id, "name": "Valid Technique"}
        
        mock_service_instance.get_technique.side_effect = get_technique_side_effect
        
        agent = PredictionAgent()
        techniques = [{"technique_id": "T1059.001", "technique_name": "PowerShell"}]
        campaign = {"campaign_id": "test-campaign"}
        
        result = agent.run(techniques, campaign)
        
        # Only T1105 should remain (T1060 filtered out as deprecated)
        assert len(result["likely_next_techniques"]) == 1
        assert result["likely_next_techniques"][0]["technique_id"] == "T1105"

    @patch('agents.prediction_agent.retrieve_likely_next_techniques_with_ids')
    @patch('agents.prediction_agent.invoke_llm')
    def test_handles_malformed_llm_response(self, mock_llm, mock_rag):
        """Test that agent handles malformed LLM JSON response gracefully"""
        mock_rag.return_value = ("Context", {"T1105"})
        mock_llm.return_value = "This is not valid JSON"
        
        agent = PredictionAgent()
        techniques = [{"technique_id": "T1059.001", "technique_name": "PowerShell"}]
        campaign = {"campaign_id": "test-campaign"}
        
        result = agent.run(techniques, campaign)
        
        assert result["likely_next_techniques"] == []
        assert "could not be parsed" in result["rationale"]

    @patch('agents.prediction_agent.retrieve_likely_next_techniques_with_ids')
    @patch('agents.prediction_agent.invoke_llm')
    def test_handles_string_technique_ids(self, mock_llm, mock_rag):
        """Test that agent handles technique IDs as strings (not dicts)"""
        mock_rag.return_value = ("Context", {"T1105", "T1055"})
        mock_llm.return_value = '''
        {
            "likely_next_techniques": ["T1105", "T1055"],
            "rationale": "String format technique IDs"
        }
        '''
        
        agent = PredictionAgent()
        techniques = [{"technique_id": "T1059.001", "technique_name": "PowerShell"}]
        campaign = {"campaign_id": "test-campaign"}
        
        result = agent.run(techniques, campaign)
        
        assert len(result["likely_next_techniques"]) == 2

    def test_validate_predicted_techniques_empty_list(self):
        """Test validation with empty prediction list"""
        result = PredictionAgent._validate_predicted_techniques([], {"T1105"})
        assert result == []

    def test_validate_predicted_techniques_invalid_format(self):
        """Test validation handles invalid item formats"""
        invalid_items = [
            123,  # number
            None,  # None
            {"no_id_field": "test"},  # dict without ID field
        ]
        result = PredictionAgent._validate_predicted_techniques(invalid_items, {"T1105"})
        assert result == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
