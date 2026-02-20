from pydantic import BaseModel, Field
from typing import Optional, Literal

class ProxyConfig(BaseModel):
    """Базовая модель конфигурации прокси"""
    server: str
    port: int = Field(ge=1, le=65535)
    
    # Common fields
    uuid: Optional = None
    password: Optional = None
    
    # Transport (Добавлены xhttp и httpupgrade)
    type: Literal = "tcp"
    path: str = "/"
    host: Optional = None
    service_name: Optional = None
    
    # Security
    security: Literal = "none"
    sni: Optional = None
    fp: str = "chrome"
    pbk: Optional = None
    sid: Optional = None
    flow: Optional = None

class ProxyNode(BaseModel):
    """Объект прокси в системе"""
    protocol: Literal
    config: ProxyConfig
    raw_uri: str
    
    # Dynamic Stats
    country: str = "UN"
    city: str = ""
    speed: float = 0.0
    latency: int = 0
    is_alive: bool = False

    @property
    def unique_id(self) -> str:
        return f"{self.protocol}://{self.config.server}:{self.config.port}"
