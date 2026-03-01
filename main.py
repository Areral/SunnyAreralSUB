import asyncio
import time
import sys
from loguru import logger

from core.settings import CONFIG
from core.parser import LinkParser
from core.engine import Inspector
from core.exporter import Exporter
from core.validator import RKNValidator

async def main():
    start_time = time.perf_counter()
    logger.info("⏣ Запуск SunnyAreral Enterprise v13 (Hardcore Trace Mode)")

    try:
        await RKNValidator.load_lists()

        parser = LinkParser()
        nodes = await parser.fetch_and_parse()

        if not nodes:
            logger.error("✘ Нет валидных ссылок. Завершение.")
            sys.exit(0)

        inspector = Inspector()
        logger.info("⚙ Пакетная проверка (Batch Engine)...")

        alive_nodes = await inspector.process_all(nodes)
        
        for node in alive_nodes:
            if node.source_url in parser.metrics:
                parser.metrics[node.source_url]["alive"] += 1

        dead_sources =[url for url, m in parser.metrics.items() if m.get("parsed", 0) > 0 and m.get("alive", 0) == 0]
        
        if dead_sources:
            logger.warning("Источники, выдавшие 0 рабочих прокси после проверки:")
            for src in dead_sources:
                safe_src = src.replace("://", ":\u200b//").replace(".", ".\u200b")
                logger.warning(f"   - {safe_src}")

        logger.success(f"⚑ Проверка завершена. Живых: {len(alive_nodes)}/{len(nodes)}")

        if alive_nodes:
            top_speed = await inspector.champion_run(alive_nodes)
            alive_nodes.sort(key=lambda x: x.speed, reverse=True)
            logger.info(f"⍟ Рекорд скорости: {top_speed} Mbps")
            Exporter.save_files(alive_nodes)
        else:
            logger.warning("⚠ Нет рабочих прокси. Файлы подписок НЕ перезаписаны.")

        duration = time.perf_counter() - start_time
        logger.info("Отправка Telegram отчета...")
        
        await Exporter.send_telegram_report(len(nodes), alive_nodes, duration, dead_sources)
        logger.info(f"✔ Завершено за {duration:.2f} сек.")
        
    except Exception as e:
        logger.exception(f"Критический сбой в main(): {e}")
        sys.exit(1)


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    else:
        try:
            import uvloop
            uvloop.install()
            logger.debug("⌁ uvloop активирован")
        except ImportError:
            pass

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.warning("Остановка пользователем")
    except Exception as e:
        logger.critical(f"FATAL ERROR ВНЕ EVENT LOOP: {e}")
        sys.exit(1)
