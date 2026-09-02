"""Private helper: drive a coroutine to completion from synchronous code,
even when called from inside an already-running event loop.

`asyncio.run` raises `RuntimeError` if a loop is already running in the
calling thread, which is exactly the situation an `async def` Target.query
implementation is called from when the caller itself is async (or under a
test harness that runs pytest inside an event loop). To make this work
unconditionally, we always drive the coroutine on a dedicated daemon thread
with its own fresh event loop.
"""

import asyncio
import threading
from typing import Any, Awaitable


def run_coroutine_blocking(coro: Awaitable[Any]) -> Any:
    """Run `coro` to completion on a dedicated daemon thread with a fresh
    event loop, blocking the calling thread until it completes.

    Safe to call from inside an already-running event loop in the calling
    thread. Exceptions raised inside `coro` are re-raised in the calling
    thread with their original traceback preserved.
    """
    result = {}

    def _runner():
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            try:
                result["value"] = loop.run_until_complete(coro)
            except BaseException as exc:  # re-raised in the calling thread below
                result["exc"] = exc
            finally:
                loop.run_until_complete(loop.shutdown_asyncgens())
        finally:
            loop.close()

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    thread.join()

    if "exc" in result:
        raise result["exc"]
    return result["value"]
