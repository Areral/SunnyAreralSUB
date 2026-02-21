from pydantic import BaseModel, Field
from typing import Optional, Literal

class ProxyConfig(BaseModel):
    server: str
    port: int = Field(ge=1, le=65535)
    uuid: Optional = None
    password: Optional = None
    method: Optional = None
    type: Literal = "tcp"
    path: str = "/"
    host: Optional = None
    service_name: Optional = None
    security: Literal = "none"
    sni: Optional = None
    fp: str = "chrome"
    pbk: Optional = None
    sid: Optional = None
    flow: Optional = None
    spx: Optional = None

class ProxyNode(BaseModel):
    protocol: Literal
    config: ProxyConfig
    raw_uri: str
    country: str = "UN"
    city: str = ""
    speed: float = 0.0
    latency: int = 0
    is_alive: bool = False

    @property
    def unique_id(self) -> str:
        uid = f"{self.protocol}://{self.config.server}:{self.config.port}"
        if self.config.uuid: uid += f"@{self.config.uuid}"
        elif self.config.password: uid += f"@{self.config.password}"
        if self.config.path and self.config.path != "/": uid += f"{self.config.path}"
        if self.config.service_name: uid += f"?svc={self.config.service_name}"
        return uid
