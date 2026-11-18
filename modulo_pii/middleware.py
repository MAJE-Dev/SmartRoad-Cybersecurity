"""Middleware FastAPI: última linha de defesa na saída da API.

Mesmo que uma rota esqueça de usar sink_resposta, o corpo da resposta JSON é
inspecionado. Se contiver PII, a resposta é trocada por 500 seguro e o evento é auditado.
"""
import json

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from .auditoria import registrar_auditoria
from .detector import detectar_pii
from .entrada import marcar_payload


ROTAS_DOCUMENTACAO = {"/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"}


class TaintMiddleware(BaseHTTPMiddleware):
    async def _interceptar_entrada(self, request) -> None:
        """Escaneia o JSON recebido, marca campos sensíveis (taint) e audita só nomes de campos/tipos."""
        if request.method not in ("POST", "PUT", "PATCH"):
            return
        if "application/json" not in request.headers.get("content-type", ""):
            return
        try:
            dados = json.loads(await request.body())
        except ValueError:
            return
        marcado, campos = marcar_payload(dados)
        request.state.payload_marcado = marcado
        if campos:
            tipos = sorted({t for _, ts in campos for t in ts})
            nomes = ", ".join(c for c, _ in campos)
            registrar_auditoria(f"{request.method} {request.url.path}", "entrada", tipos, False,
                                f"campos sensiveis marcados (taint): {nomes}")

    async def dispatch(self, request, call_next):
        await self._interceptar_entrada(request)
        resp = await call_next(request)
        # A documentação gerada pelo FastAPI descreve os campos (ex.: "cadeirante") e não carrega
        # dado de cidadão: inspecioná-la gera falso positivo e quebra o Swagger.
        if request.url.path in ROTAS_DOCUMENTACAO:
            return resp
        if "application/json" not in resp.headers.get("content-type", ""):
            return resp
        corpo = b"".join([chunk async for chunk in resp.body_iterator])
        texto = corpo.decode("utf-8", errors="ignore")
        tipos = {a.tipo for a in detectar_pii(texto)}
        if tipos:
            registrar_auditoria(
                f"{request.method} {request.url.path}", "api", list(tipos), True,
                "middleware bloqueou resposta com PII",
            )
            return JSONResponse(
                status_code=500,
                content={"erro": "Resposta bloqueada: continha dado pessoal.", "tipos": sorted(tipos)},
            )
        registrar_auditoria(f"{request.method} {request.url.path}", "api", [], False, "resposta limpa")
        headers = {k: v for k, v in resp.headers.items() if k.lower() != "content-length"}
        return Response(content=corpo, status_code=resp.status_code, headers=headers,
                        media_type=resp.media_type)
