import os
from inspect import isawaitable
from typing import Optional


async def enqueue_analysis_job(job_id: str) -> bool:
    """Enqueue a job when ARQ is available; otherwise leave it queued for mocks."""
    redis_url = os.getenv("KAVACH_REDIS_URL", "redis://localhost:6379/0")

    try:
        from arq import create_pool
        from arq.connections import RedisSettings
    except ImportError:
        return False

    redis = None
    try:
        settings = _redis_settings_from_url(redis_url)
        redis = await create_pool(settings)
        await redis.enqueue_job("run_triage_and_static_job", job_id)
        return True
    except Exception:
        return False
    finally:
        if redis is not None:
            close = getattr(redis, "aclose", None) or getattr(redis, "close", None)
            if close is not None:
                result = close()
                if isawaitable(result):
                    await result


def _redis_settings_from_url(redis_url: str) -> "RedisSettings":
    from arq.connections import RedisSettings

    if not redis_url.startswith("redis://"):
        return RedisSettings(conn_retries=0)

    without_scheme = redis_url.removeprefix("redis://")
    host_port_db = without_scheme.split("/")
    host_port = host_port_db[0]
    database: Optional[int] = int(host_port_db[1]) if len(host_port_db) > 1 and host_port_db[1] else 0

    if ":" in host_port:
        host, port_text = host_port.split(":", 1)
        return RedisSettings(host=host, port=int(port_text), database=database, conn_retries=0)

    return RedisSettings(host=host_port, database=database, conn_retries=0)
