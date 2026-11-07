"""Run ASGI apps on real sockets in background threads.

Used by the propagation benchmark and the Phase 5 tests: the trust service and
each gateway get their own uvicorn server and port, so the HTTP calls, SSE
stream, and caches behave exactly as they would in separate processes.
"""

import socket
import threading
import time

import uvicorn


class ServerThread:
    def __init__(self, app, host: str = "127.0.0.1", port: int = 0):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))  # port 0 = OS picks a free port
        self.port = self._sock.getsockname()[1]
        self.url = f"http://{host}:{self.port}"
        config = uvicorn.Config(app, log_level="warning", lifespan="on", timeout_graceful_shutdown=1)
        self.server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self._sock]}, daemon=True)

    def start(self, timeout: float = 10.0) -> "ServerThread":
        self._thread.start()
        deadline = time.monotonic() + timeout
        while not self.server.started:
            if time.monotonic() > deadline or not self._thread.is_alive():
                raise RuntimeError(f"server on {self.url} failed to start")
            time.sleep(0.01)
        return self

    def stop(self, timeout: float = 10.0) -> None:
        self.server.should_exit = True
        self._thread.join(timeout)
        self._sock.close()

    def __enter__(self) -> "ServerThread":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
