"""Hindsight Agent Memory Service Integration."""

import logging
from typing import Dict, Any, List, Optional
import requests
from ..config import get_settings

logger = logging.getLogger(__name__)

class InvestigationMemoryService:
    def __init__(self):
        self.settings = get_settings()
        self.api_key = self.settings.hindsight_api_key
        self.base_url = self.settings.hindsight_base_url.rstrip("/")
        self.default_bank = self.settings.hindsight_default_bank
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        } if self.api_key else {"Content-Type": "application/json"}
        
        self.enabled = bool(self.api_key)
        if not self.enabled:
            logger.warning("Hindsight API key not configured. Memory service is disabled.")

    def _get_bank_id(self, entity_id: str) -> str:
        """Get or determine the bank ID for an entity."""
        if entity_id:
            return f"entity-{entity_id}"
        return self.default_bank

    def recall(self, query: str, entity_id: str = None, limit: int = 5) -> List[Dict[str, Any]]:
        """Recall historical memories relevant to the query."""
        if not self.enabled:
            return []
            
        bank_id = self._get_bank_id(entity_id)
        url = f"{self.base_url}/v1/memory/{bank_id}/recall"
        
        try:
            response = requests.post(
                url,
                headers=self.headers,
                json={"query": query, "limit": limit},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            return data.get("memories", [])
        except Exception as e:
            logger.error(f"Failed to recall memories from Hindsight: {e}")
            return []

    def retain(self, content: str, metadata: Dict[str, Any] = None, entity_id: str = None) -> bool:
        """Retain a new memory."""
        if not self.enabled:
            return False
            
        bank_id = self._get_bank_id(entity_id)
        url = f"{self.base_url}/v1/memory/{bank_id}/retain"
        
        payload = {"content": content}
        if metadata:
            payload["metadata"] = metadata
            
        try:
            response = requests.post(
                url,
                headers=self.headers,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to retain memory in Hindsight: {e}")
            return False

    def reflect(self, query: str, entity_id: str = None) -> Optional[str]:
        """Synthesize memories to answer a broader question."""
        if not self.enabled:
            return None
            
        bank_id = self._get_bank_id(entity_id)
        url = f"{self.base_url}/v1/memory/{bank_id}/reflect"
        
        try:
            response = requests.post(
                url,
                headers=self.headers,
                json={"query": query},
                timeout=20
            )
            response.raise_for_status()
            data = response.json()
            return data.get("reflection")
        except Exception as e:
            logger.error(f"Failed to synthesize memory in Hindsight: {e}")
            return None
