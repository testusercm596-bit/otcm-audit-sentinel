"""
Application settings and configuration loader
"""
import os
from typing import Optional
from dotenv import load_dotenv
from dataclasses import dataclass

# Load environment variables from .env file
load_dotenv()


@dataclass
class DatabaseConfig:
    """Database configuration"""
    url: str
    pool_size: int = 10
    max_overflow: int = 20
    echo: bool = False


@dataclass
class ContentManagerConfig:
    """Content Manager API configuration"""
    base_url: str
    username: str
    password: str
    domain: Optional[str] = None
    timeout: int = 30


@dataclass
class AIConfig:
    """AI/OpenAI configuration - Legacy/General"""
    openai_api_key: str
    model: str = "gpt-4"
    temperature: float = 0.7
    max_tokens: int = 2000


@dataclass
class SentinelAIConfig:
    """Sentinel agent AI configuration"""
    api_key: str
    api_base: str
    model: str
    temperature: float = 0.7
    max_tokens: int = 2000


@dataclass
class HallucinatorAIConfig:
    """Hallucinator agent AI configuration"""
    api_key: str
    api_base: str
    model: str
    temperature: float = 0.7
    max_tokens: int = 2000


@dataclass
class SentinelConfig:
    """Sentinel agent configuration"""
    sensitivity: float = 0.7
    batch_size: int = 100
    enable_realtime: bool = True


@dataclass
class HallucinatorConfig:
    """Hallucinator agent configuration"""
    creativity: float = 0.8
    max_scenarios: int = 10
    enable_automated_testing: bool = False


class Settings:
    """Application settings manager"""
    
    def __init__(self):
        self.database = DatabaseConfig(
            url=os.getenv('DATABASE_URL', 'postgresql://localhost/otcm_audit')
        )
        
        self.content_manager = ContentManagerConfig(
            base_url=os.getenv('CM_BASE_URL', ''),
            username=os.getenv('CM_USERNAME', ''),
            password=os.getenv('CM_PASSWORD', ''),
            domain=os.getenv('CM_DOMAIN', None)
        )
        
        self.ai = AIConfig(
            openai_api_key=os.getenv('OPENAI_API_KEY', ''),
            model=os.getenv('AI_MODEL', 'gpt-4'),
            temperature=float(os.getenv('AI_TEMPERATURE', '0.7'))
        )
        
        # Sentinel AI Configuration
        self.sentinel_ai = SentinelAIConfig(
            api_key=os.getenv('SENTINEL_API_KEY', os.getenv('OPENAI_API_KEY', '')),
            api_base=os.getenv('SENTINEL_API_BASE', 'https://sandbox.aviator-model.bp.anthos.otxlab.net/v1'),
            model=os.getenv('SENTINEL_MODEL', 'openai/meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8'),
            temperature=float(os.getenv('SENTINEL_TEMPERATURE', '0.7')),
            max_tokens=int(os.getenv('SENTINEL_MAX_TOKENS', '2000'))
        )
        
        # Hallucinator AI Configuration
        self.hallucinator_ai = HallucinatorAIConfig(
            api_key=os.getenv('HALLUCINATOR_API_KEY', os.getenv('OPENAI_API_KEY', '')),
            api_base=os.getenv('HALLUCINATOR_API_BASE', 'https://sandbox.aviator-model.bp.anthos.otxlab.net/v1'),
            model=os.getenv('HALLUCINATOR_MODEL', 'openai/meta-llama/Llama-3.3-70B-Instruct'),
            temperature=float(os.getenv('HALLUCINATOR_TEMPERATURE', '0.7')),
            max_tokens=int(os.getenv('HALLUCINATOR_MAX_TOKENS', '2000'))
        )
        
        self.sentinel = SentinelConfig(
            sensitivity=float(os.getenv('SENTINEL_SENSITIVITY', '0.7')),
            enable_realtime=os.getenv('SENTINEL_REALTIME', 'true').lower() == 'true'
        )
        
        self.hallucinator = HallucinatorConfig(
            creativity=float(os.getenv('HALLUCINATOR_CREATIVITY', '0.8')),
            enable_automated_testing=os.getenv('HALLUCINATOR_AUTO', 'false').lower() == 'true'
        )
    
    def validate(self) -> bool:
        """Validate that all required settings are present"""
        required_settings = [
            (self.database.url, "DATABASE_URL"),
            (self.content_manager.base_url, "CM_BASE_URL"),
            (self.content_manager.username, "CM_USERNAME"),
            (self.content_manager.password, "CM_PASSWORD"),
            (self.sentinel_ai.api_key, "SENTINEL_API_KEY or OPENAI_API_KEY"),
            (self.hallucinator_ai.api_key, "HALLUCINATOR_API_KEY or OPENAI_API_KEY")
        ]
        
        missing = [name for value, name in required_settings if not value]
        
        if missing:
            print(f"Missing required settings: {', '.join(missing)}")
            return False
        
        return True


# Global settings instance
settings = Settings()
