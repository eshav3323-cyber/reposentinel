import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

from app.routes.scanners import router as scanners_router
from app.routes.scans import router as scans_router
from app.routes.attack_graph import router as attack_graph_router
from app.routes.remediation import router as remediation_router


MAX_SCAN_REQUEST_BYTES = 21 * 1024 * 1024


class ScanUploadLimitMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        is_scan_upload = (
            scope["type"] == "http"
            and scope.get("method") == "POST"
            and scope.get("path") == "/api/scans"
        )

        if not is_scan_upload:
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")

        if content_length:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = -1

            if declared_size > MAX_SCAN_REQUEST_BYTES:
                await self._too_large(send)
                return

        chunks: list[bytes] = []
        total_size = 0

        while True:
            message = await receive()

            if message["type"] == "http.disconnect":
                return

            if message["type"] != "http.request":
                continue

            chunk = message.get("body", b"")
            total_size += len(chunk)

            if total_size > MAX_SCAN_REQUEST_BYTES:
                await self._too_large(send)
                return

            chunks.append(chunk)

            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        replayed = False

        async def replay_receive():
            nonlocal replayed

            if not replayed:
                replayed = True
                return {
                    "type": "http.request",
                    "body": body,
                    "more_body": False,
                }

            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _too_large(send: Send) -> None:
        body = b'{"detail":"Request body exceeds the 21 MiB limit."}'

        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })

        await send({
            "type": "http.response.body",
            "body": body,
        })


app = FastAPI(
    title="RepoSentinel Health API",
    description=(
        "Defensive security analysis for healthcare software repositories."
    ),
    version="0.1.0",
)

app.add_middleware(ScanUploadLimitMiddleware)

app.include_router(scanners_router)
app.include_router(scans_router)
app.include_router(attack_graph_router)
app.include_router(remediation_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,"
            "http://localhost:4173,http://127.0.0.1:4173",
        ).split(",")
        if origin.strip()
    ],
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/")
def root():
    return {
        "name": "RepoSentinel Health",
        "status": "running",
        "version": "0.1.0",
        "message": "Healthcare repository security analysis API is ready.",
    }


@app.get("/api/status")
def api_status():
    return {**root(), "health": health_check()}


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "reposentinel-backend",
        "python_api": "FastAPI",
    }
