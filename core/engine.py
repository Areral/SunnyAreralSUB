import asyncio
import json
import os
import subprocess
import time
import signal
import aiohttp
from aiohttp_socks import ProxyConnector
from loguru import logger
from typing import List

from core.models import ProxyNode
from core.settings import CONFIG

class BatchEngine:
    """
    Движок пакетной проверки.
    Запускает один экземпляр Sing-box для N прокси одновременно.
    Решает проблему 'Process Hell'.
    """
    
    BASE_PORT = 10000  # Начальный порт для тестов

    @staticmethod
    def _generate_batch_config(nodes: List[ProxyNode]) -> dict:
        """Генерирует единый JSON для пачки прокси"""
        inbounds = []
        outbounds = []
        rules = []
        
        # 1. Создаем пары Inbound -> Outbound для каждого прокси
        for i, node in enumerate(nodes):
            local_port = BatchEngine.BASE_PORT + i
            tag = f"proxy-{i}"
            
            # Входящий SOCKS на уникальном порту
            inbounds.append({
                "type": "socks",
                "tag": f"in-{i}",
                "listen": "127.0.0.1",
                "listen_port": local_port
            })
            
            # Исходящий прокси (конвертируем из нашей модели)
            outbound = BatchEngine._node_to_outbound(node, tag)
            outbounds.append(outbound)
            
            # Правило маршрутизации: трафик с in-X идет в proxy-X
            rules.append({
                "inbound": [f"in-{i}"],
                "outbound": tag
            })

        # 2. Добавляем Direct и DNS
        outbounds.append({"type": "direct", "tag": "direct"})
        
        return {
            "log": {"level": "panic", "output": "discard"},
            "dns": {
                "servers": [
                    {"tag": "remote", "address": "1.1.1.1", "detour": "direct"}, # Резолвим снаружи туннеля (Fix DNS Trap)
                ],
                "strategy": "ipv4_only"
            },
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": {
                "rules": rules,
                "final": "direct" # Fallback, но правила выше перехватят всё
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
            
        # Transport
        if c.type == "ws":
            base["transport"] = {"type": "ws", "path": c.path, "headers": {"Host": c.host}}
        elif c.type == "grpc":
            base["transport"] = {"type": "grpc", "service_name": c.service_name}
        elif c.type in ["xhttp", "httpupgrade"]:
            base["transport"] = {"type": "httpupgrade", "path": c.path or "/", "host": c.host or ""}
            
        # TLS
        if c.security in ["tls", "reality", "auto"]:
            tls = {
                "enabled": True, 
                "server_name": c.sni or c.host or c.server,
                "utls": {"enabled": True, "fingerprint": c.fp or "chrome"}
            }
            if c.security == "reality":
                tls["reality"] = {"enabled": True, "public_key": c.pbk, "short_id": c.sid or ""}
                if c.spx and c.spx != "/": tls["reality"]["spider_x"] = c.spx
            base["tls"] = tls
            
        return base

    async def check_batch(self, nodes: List[ProxyNode]) -> List[ProxyNode]:
        """Запускает проверку пачки"""
        if not nodes: return []
        
        alive_nodes = []
        config_path = "data/batch_config.json"
        os.makedirs("data", exist_ok=True)
        
        proc = None
        try:
            # 1. Генерируем конфиг
            with open(config_path, "w") as f:
                json.dump(self._generate_batch_config(nodes), f)
            
            # 2. Запускаем ядро (ОДИН РАЗ на 50 прокси!)
            proc = subprocess.Popen(
                ["sing-box", "run", "-c", config_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
            await asyncio.sleep(2.5) # Даем ядру прогрузиться
            
            if proc.poll() is not None:
                logger.error("Sing-box batch process died immediately!")
                return []

            # 3. Параллельная проверка через aiohttp
            # Создаем задачи для каждого узла на его порту
            tasks = []
            for i, node in enumerate(nodes):
                port = self.BASE_PORT + i
                tasks.append(self._http_check(node, port))
            
            # Ждем выполнения всех проверок
            results = await asyncio.gather(*tasks)
            alive_nodes = [n for n in results if n is not None]
            
        except Exception as e:
            logger.error(f"Batch error: {e}")
        finally:
            # Убиваем ядро
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    proc.wait(timeout=2)
                except:
                    try: proc.kill()
                    except: pass
            if os.path.exists(config_path): os.remove(config_path)
            
        return alive_nodes

    async def _http_check(self, node: ProxyNode, port: int) -> Optional[ProxyNode]:
        """Индивидуальная проверка через локальный порт"""
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
        # Таймаут на весь тест
        timeout = aiohttp.ClientTimeout(total=CONFIG.system.get('http_timeout', 20))
        
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                # 1. Latency (Real Request)
                t0 = time.perf_counter()
                async with session.get("http://www.gstatic.com/generate_204", allow_redirects=False) as resp:
                    if resp.status != 204: raise Exception(f"Status {resp.status}")
                    node.latency = int((time.perf_counter() - t0) * 1000)

                # 2. Speed (5MB)
                url = CONFIG.checking.get('speedtest_url', "http://speed.cloudflare.com/__down?bytes=5000000")
                t_start = time.perf_counter()
                async with session.get(url) as resp:
                    if resp.status != 200: raise Exception("Download fail")
                    
                    total = 0
                    async for chunk in resp.content.iter_chunked(65536):
                        total += len(chunk)
                    
                    dur = time.perf_counter() - t_start
                    if dur < 0.2: dur = 0.2 # Защита от деления на 0
                    
                    speed = (total * 8) / (dur * 1_000_000)
                    if speed > 3000: speed = 0 # Фильтр багов
                    node.speed = round(speed, 1)

                # 3. Geo
                try:
                    async with session.get("https://ipwho.is/", timeout=4) as geo:
                        data = await geo.json()
                        if data.get('success'): node.country = data.get('country_code', 'UN')
                except: pass

                # Финальный вердикт
                if node.speed >= CONFIG.checking.get('min_speed', 2.0):
                    return node
                    
        except Exception as e:
            # logger.debug(f"Node failed: {e}") # Можно включить для отладки
            return None
        return None

class Inspector:
    """Интерфейс для main.py"""
    def __init__(self):
        self.batch_engine = BatchEngine()

    async def process_all(self, nodes: List[ProxyNode]) -> List[ProxyNode]:
        """Обрабатывает все узлы пакетами"""
        alive_total = []
        batch_size = CONFIG.BATCH_SIZE
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
        """Отдельный тест для чемпиона (одиночный запуск)"""
        # Для чемпиона используем старый метод одиночного запуска, 
        # эмулируя пакет из 1 элемента
        results = await self.batch_engine.check_batch([node])
        if results:
            return results[0].speed
        return 0.0
