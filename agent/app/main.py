"""The agent's web API. Only the gateway may call it (ADR-4):

- it listens on 127.0.0.1 only (see the run command in AGENTS.md), so other machines
  cannot reach it at all;
- every request, even for a page that does not exist, needs the service token.

It has no database access and keeps nothing between requests (ADR-3): everything it
needs arrives with each request.
"""

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import config, security
from app.investigation import investigate
from app.models import InvestigateRequest

# The gateway's incidents are capped at 256 KB; this leaves room for the baseline.
MAX_BODY_BYTES = 1024 * 1024


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    config.service_token()  # refuse to start without a usable token
    yield


# No /docs, /redoc or /openapi.json: there is nothing to browse, and they would be
# readable without the token.
app = FastAPI(title="agent", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


def error(status: int, message: str, fields: dict[str, str] | None = None) -> JSONResponse:
    body: dict[str, object] = {"error": message}
    if fields:
        body["fields"] = fields
    headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
    return JSONResponse(body, status_code=status, headers=headers)


@app.middleware("http")
async def guard(request: Request, call_next):  # type: ignore[no-untyped-def]
    # 1. Who is calling? Checked first, so nothing else is revealed to anyone without the token.
    if not security.is_authorised(request.headers.get("authorization"), config.service_token()):
        return error(401, "Unauthorized")
    # 2. Bodies must state their size, and not be too big, before anything reads them.
    if request.method == "POST":
        length = request.headers.get("content-length")
        if length is None or not length.isdigit():
            return error(411, "Request body must state its length")
        if int(length) > MAX_BODY_BYTES:
            return error(413, "Request body is too large")
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def invalid_request(_: Request, exc: RequestValidationError) -> JSONResponse:
    # FastAPI's default answer repeats the rejected input back; ours names the field only.
    fields = {".".join(str(part) for part in e["loc"][1:]) or "body": e["msg"] for e in exc.errors()}
    return error(400, "Validation failed", fields)


@app.exception_handler(StarletteHTTPException)
async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    messages = {404: "Not found", 405: "Method not allowed"}
    return error(exc.status_code, messages.get(exc.status_code, "Request refused"))


@app.get("/internal/health")
def health() -> dict[str, str]:
    return {"status": "UP", "service": "agent"}


@app.post("/internal/investigate")
def investigate_incident(request: InvestigateRequest) -> StreamingResponse:
    def lines() -> Iterator[str]:
        for event in investigate(request):
            yield event.model_dump_json() + "\n"

    return StreamingResponse(lines(), media_type="application/x-ndjson")
