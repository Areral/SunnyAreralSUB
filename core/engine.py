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
    """
    Движок пакетной проверки.
    Запускает один экземпляр Sing-box для N прокси одновременно.
    Решает проблему 'Process Hell'.
    """
    
    BASE_PORT = 10000

    # Пул API для обхода Rate Limits. Формат: (URL, Ключ в JSON для кода страны)
    GEO_APIS =

    @staticmethod
    def _generate_batch_config(nodes: List) -> dict:
        """Генерирует единый JSON для пачки прокси"""
        inbounds = []
        outbounds = []
        rules =[]
        
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
                "inbound":,
                "outbound": tag
            })

        outbounds.append({"type": "direct", "tag": "direct"})
        
        return {
            "log": {"level": "panic", "output": "discard"},
            "dns": {
                "servers":,
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
        """Конвертер модели ProxyNode в конфиг Sing-box"""
        c = node.config
        base = {"tag": tag, "server": c.server, "server_port": c.port}
        
        if node.protocol == "vless":
            base.update({"type": "vless", "uuid": c.uuid, "flow": c.flow or "", "packet_encoding": "xudp"})
        elif node.protocol == "vmess":
            base.update({"type": "vmess", "uuid": c.uuid, "security": "auto", "packet_encoding": "xudp"})
        elif node.protocol == "trojan":
            base.update({"type": "trojan", "password": c.password})
        elif node.protocol == "ss":
            base.update({"type": "shadowsocks", "method": c.method, "password": c.password})
            
        if c.type == "ws":
            base = {"type": "ws", "path": c.path, "headers": {"Host": c.host}}
        elif c.type == "grpc":
            base = {"type": "grpc", "service_name": c.service_name}
        elif c.type in:
            base = {"type": "httpupgrade", "path": c.path or "/", "host": c.host or ""}
            
        if c.security in:
            tls = {
                "enabled": True, 
                "server_name": c.sni or c.host or c.server,
                "utls": {"enabled": True, "fingerprint": c.fp or "chrome"}
            }
            if c.security == "reality":
                tls = {"enabled": True, "public_key": c.pbk, "short_id": c.sid or ""}
                if c.spx and c.spx != "/": tls = c.spx
            base = tls
            
        return base

    async def check_batch(self, nodes: List, is_champion: bool = False) -> List:
        """Запускает проверку пачки"""
        if not nodes: return []
        
        alive_nodes =[]
        config_path = "data/batch_config.json"
        os.makedirs("data", exist_ok=True)
        
        proc = None
        try:
            with open(config_path, "w") as f:
                json.dump(self._generate_batch_config(nodes), f)
            
            proc = subprocess.Popen(,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
            await asyncio.sleep(2.5) 
            
            if proc.poll() is not None:
                logger.error("Sing-box batch process died immediately!")
                return []

            tasks =[]
            for i, node in enumerate(nodes):
                port = self.BASE_PORT + i
                tasks.append(self._http_check(node, port, is_champion))
            
            results = await asyncio.gather(*tasks)
            alive_nodes =
            
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

    async def _http_check(self, node: ProxyNode, port: int, is_champion: bool) -> Optional:
        """Индивидуальная проверка через локальный порт"""
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
        timeout = aiohttp.ClientTimeout(total=CONFIG.system.get('http_timeout', 25))
        headers = {"User-Agent": CONFIG.system.get('user_agent', 'Mozilla/5.0')}
        
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
                # 1. Latency (Real Request)
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

                # Финальный вердикт
                if node.speed >= CONFIG.checking.get('min_speed', 2.0):
                    return node
                    
        except Exception:
            return None
        return None

class Inspector:
    """Интерфейс для main.py"""
    def __init__(self):
        self.batch_engine = BatchEngine()

    async def process_all(self, nodes: List) -> List:
        """Обрабатывает все узлы пакетами"""
        alive_total =[]
        batch_size = getattr(CONFIG, 'BATCH_SIZE', 50)
        total = len(nodes)
        
        logger.info(f"🚀 Запуск проверки: {total} узлов, размер пакета: {batch_size}")
        
        for i in range(0, total, batch_size):
            batch = nodes
            logger.info(f"📦 Пакет {i // batch_size + 1}: проверка {len(batch)} узлов...")
            
            results = await self.batch_engine.check_batch(batch)
            alive_total.extend(results)
            
            logger.info(f"   ✨ Живых в пакете: {len(results)}")
            
        return alive_total
    
    async def champion_run(self, node: ProxyNode) -> float:
        """Отдельный тест для чемпиона с тяжелым файлом"""
        results = await self.batch_engine.check_batch(, is_champion=True)
        if results:
            return results.speed
        return 0.0
