"""ROTAS DE DEMONSTRAÇÃO. Existem só para mostrar o Taint Analysis bloqueando vazamentos.

Cada rota tenta de propósito vazar um dado sensível. O bloqueio é o comportamento esperado.
NÃO fazem parte da funcionalidade do SmartRoad e devem ser desligadas em produção.
"""
import logging

from fastapi import APIRouter, Request

from modulo_pii.sanitizers import mascarar_cpf, mascarar_generico
from modulo_pii.sinks import sink_log, sink_resposta
from modulo_pii.taint import marcar

router = APIRouter(prefix="/demo", tags=["demo-vazamento"])

CPF_FICTICIO = "529.982.247-25"  # CPF válido, fictício (gerado para teste)


@router.get("/vaza-cpf-no-log")
def vaza_cpf_log():
    """Cenário 1: CPF cru vai para o log -> BLOQUEADO."""
    cpf = marcar(CPF_FICTICIO, {"CPF"})
    sink_log(f"Usuário logado: {cpf}", origem="GET /demo/vaza-cpf-no-log")
    return {"ok": True}


@router.get("/cpf-mascarado-no-log")
def cpf_mascarado_log():
    """Cenário 2: CPF mascarado no log -> PERMITIDO."""
    cpf = marcar(CPF_FICTICIO, {"CPF"})
    sink_log(f"Usuário logado: {mascarar_cpf(cpf)}", origem="GET /demo/cpf-mascarado-no-log")
    return {"ok": True, "cpf": mascarar_cpf(cpf)}


@router.get("/vaza-senha-na-resposta")
def vaza_senha():
    """Cenário 3: senha na resposta da API -> BLOQUEADO."""
    senha = marcar("senha: MinhaSenha123", {"SENHA"})
    return sink_resposta({"debug": senha}, origem="GET /demo/vaza-senha-na-resposta")


@router.get("/vaza-sem-sink")
def vaza_sem_sink():
    """Cenário 4: rota 'esqueceu' o sink e devolve o CPF -> o MIDDLEWARE bloqueia."""
    return {"cpf_do_usuario": CPF_FICTICIO}


@router.get("/logger-direto")
def logger_direto():
    """Cenário 5: logger.info(...) direto, SEM usar o sink, com dado de saúde -> o LOG é bloqueado.

    A rota responde 200 (a requisição não falha), mas a mensagem que chega ao log é
    '[LOG BLOQUEADO: dado pessoal detectado]' e o evento fica na auditoria.
    """
    dados_de_saude = marcar("laudo médico: diabetes tipo 2", {"SAUDE"})
    logging.getLogger("smartroad.demo").info("dados_de_saude=%s", dados_de_saude)
    return {"ok": True, "obs": "o logger.info foi interceptado; confira a auditoria"}


@router.post("/documento")
async def documento(request: Request):
    """Cenário 6 (exemplo do professor): JSON com a chave 'documento' é marcado como PII na ENTRADA
    e só volta mascarado.  Teste com: {"documento": "123.456.789-00"}"""
    marcado = getattr(request.state, "payload_marcado", {}) or {}
    doc = marcado.get("documento", "")
    tipos = sorted(getattr(doc, "tags", ()))
    mascarado = mascarar_generico(str(doc), tipos[0] if tipos else "")
    return sink_resposta({"marcado_como": tipos, "documento": mascarado}, origem="POST /demo/documento")
