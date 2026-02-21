import asyncio
import json
import os
import subprocess
import time
import signal
import random
import aiohttp
from aiohttp_socks import ProxyConnector
from loguru import logger
from typing import List, Optional

from core.models import ProxyNode
from core.settings import CONFIG

class BatchEngine:
    BASE_PORT = 10000

    # Пул API для ротации
    GEO_APIS = [
        ("https://ipwho.is/", "country_code"),
        ("http://ip-api.com/json/", "countryCode"),
        ("https://api.country.is/", "country"),
        ("https://ipinfo.io/json", "country") 
    ]

    @staticmethod
    def _generate_batch_config(nodes: List[ProxyNode]) -> dict:
        inbounds = []
        outbounds = []
        rules = []
        
        for i, node in enumerate(nodes):
            local_port = BatchEngine.BASE_PORT + i
            tag = f"proxy-{i}"
            
            inbounds.append({
                "type": "socks",
                "tag": f"in-{i}",
                "listen": "127.0.0.1",
                "listen_port": local_port
            })
            
            outbound = BatchEngine._node_to_outbound(node, tag)
            outbounds.append(outbound)
            
            rules.append({
                "inbound": [f"in-{i}"],
                "outbound": tag
            })

        outbounds.append({"type": "direct", "tag": "direct"})
        
        return {
            "log": {"level": "panic", "output": "discard"},
            "dns": {
                "servers": [
                    {"tag": "remote", "address": "1.1.1.1", "detour": "direct"}
                ],
                "strategy": "ipv4_only"
            },
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": {
                "rules": rules,
                "final": "direct"
            }
        }

    @staticmethod
    def _node_to_outbound(node: ProxyNode, tag: str) -> dict:
        c = node.config
        base = {"tag": tag, "server": c.server, "server_port": c.port}
        
        # Protocol specifics
        if node.protocol == "vless":
            base.update({"type": "vless", "uuid": c.uuid, "flow": c.flow or "", "packet_encoding": "xudp"})
        elif node.protocol == "vmess":
            base.update({"type": "vmess", "uuid": c.uuid, "security": "auto", "packet_encoding": "xudp"})
        elif node.protocol == "trojan":
            base.update({"type": "trojan", "password": c.password})
        elif node.protocol == "ss":
            base.update({"type": "shadowsocks", "method": c.method, "password": c.password})
            
        # Transport
        if c.type == "ws":
            base["transport"] = {"type": "ws", "path": c.path, "headers": {"Host": c.host}}
        elif c.type == "grpc":
            base["transport"] = {"type": "grpc", "service_name": c.service_name}
        elif c.type in ["xhttp", "httpupgrade"]:
            base["transport"] = {"type": "httpupgrade", "path": c.path or "/", "host": c.host or ""}
            
        # TLS / Reality
        if c.security in ["tls", "reality", "auto"]:
            tls = {
                "enabled": True, 
                "server_name": c.sni or c.host or c.server,
                "utls": {"enabled": True, "fingerprint": c.fp or "chrome"}
            }
            if c.security == "reality":
                tls["reality"] = {"enabled": True, "public_key": c.pbk, "short_id": c.sid or ""}
                if c.spx and c.spx != "/": 
                    tls["reality"]["spider_x"] = c.spx
            base["tls"] = tls
            
        return base

    async def check_batch(self, nodes: List[ProxyNode], is_champion: bool = False) -> List[ProxyNode]:
        if not nodes: return []
        
        alive_nodes = []
        config_path = "data/batch_config.json"
        os.makedirs("data", exist_ok=True)
        
        proc = None
        try:
            with open(config_path, "w") as f:
                json.dump(self._generate_batch_config(nodes), f)
            
            proc = subprocess.Popen(
                ["sing-box", "run", "-c", config_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
            await asyncio.sleep(2.5)
            
            if proc.poll() is not None:
                logger.error("Sing-box batch process died immediately!")
                return []

            tasks = []
            for i, node in enumerate(nodes):
                port = self.BASE_PORT + i
                tasks.append(self._http_check(node, port, is_champion))
            
            results = await asyncio.gather(*tasks)
            alive_nodes = [n for n in results if n is not None]
            
        except Exception as e:
            logger.error(f"Batch error: {e}")
        finally:
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    proc.wait(timeout=2)
                except:
                    try: proc.kill()
                    except: pass
            if os.path.exists(config_path): os.remove(config_path)
            
        return alive_nodes

    async def _http_check(self, node: ProxyNode, port: int, is_champion: bool) -> Optional[ProxyNode]:
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
        timeout = aiohttp.ClientTimeout(total=CONFIG.system.get('http_timeout', 25))
        headers = {"User-Agent": CONFIG.system.get('user_agent', 'Mozilla/5.0')}
        
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
                # 1. Latency
                t0 = time.perf_counter()
                async with session.get("http://www.gstatic.com/generate_204", allow_redirects=False) as resp:
                    if resp.status != 204: raise Exception(f"Status {resp.status}")
                    node.latency = int((time.perf_counter() - t0) * 1000)

                # 2. Speed
                if is_champion:
                    url = CONFIG.checking.get('champion_test_url', "http://speed.cloudflare.com/__down?bytes=25000000")
                else:
                    url = CONFIG.checking.get('speedtest_url', "http://speed.cloudflare.com/__down?bytes=5000000")
                
                t_start = time.perf_counter()
                async with session.get(url) as resp:
                    if resp.status != 200: raise Exception("Download fail")
                    
                    total = 0
                    async for chunk in resp.content.iter_chunked(65536):
                        total += len(chunk)
                    
                    dur = time.perf_counter() - t_start
                    if dur < 0.2: dur = 0.2
                    
                    speed = (total * 8) / (dur * 1_000_000)
                    if speed > 3000: speed = 0 
                    node.speed = round(speed, 1)

                # 3. Geo-API Rotation
                api_url, cc_key = random.choice(self.GEO_APIS)
                try:
                    async with session.get(api_url, timeout=5) as geo:
                        if geo.status == 200:
                            data = await geo.json(content_type=None)
                            cc = data.get(cc_key)
                            if cc and isinstance(cc, str) and len(cc) == 2:
                                node.country = cc.upper()
                except Exception:
                    pass

                if node.speed >= CONFIG.checking.get('min_speed', 2.0):
                    return node
                    
        except Exception:
            return None
        return None

class Inspector:
    def __init__(self):
        self.batch_engine = BatchEngine()

    async def process_all(self, nodes: List[ProxyNode]) -> List[ProxyNode]:
        alive_total = []
        batch_size = getattr(CONFIG, 'BATCH_SIZE', 50)
        total = len(nodes)
        
        logger.info(f"🚀 Запуск проверки: {total} узлов, размер пакета: {batch_size}")
        
        for i in range(0, total, batch_size):
            batch = nodes[i : i + batch_size]
            logger.info(f"📦 Пакет {i // batch_size + 1}: проверка {len(batch)} узлов...")
            
            results = await self.batch_engine.check_batch(batch)
            alive_total.extend(results)
            
            logger.info(f"   ✨ Живых в пакете: {len(results)}")
            
        return alive_total
    
    async def champion_run(self, node: ProxyNode) -> float:
        results = await self.batch_engine.check_batch([node], is_champion=True)
        if results:
            return results[0].speed
        return 0.0
