"""Indicador de Risco Cidadão (0 a 100), calculado a partir da auditoria.

Cada evento de PII soma: peso do tipo x fator de exposição do destino.
Vazamento BLOQUEADO conta pouco (o sistema protegeu); vazamento NÃO bloqueado conta cheio.
Eventos de ENTRADA (dado marcado ao chegar) não são saída: entram nas contagens de PII detectada,
mas não pesam no risco nem em "vazados/bloqueados".
"""
from collections import Counter

from .regras import PESO

EXPOSICAO = {"api": 1.5, "arquivo": 1.2, "log": 1.0, "llm": 1.3}
FATOR_BLOQUEADO = 0.1


def _saidas(eventos: list[dict]) -> list[dict]:
    return [e for e in eventos if e.get("destino") != "entrada"]


def risco_cidadao(eventos: list[dict]) -> int:
    total = 0.0
    for e in _saidas(eventos):
        for tipo in e.get("tipos", []):
            base = PESO.get(tipo, 5) * EXPOSICAO.get(e.get("destino"), 1.0)
            total += base * (FATOR_BLOQUEADO if e.get("bloqueado") else 1.0)
    return min(100, round(total))


def nivel(score: int) -> str:
    return "Baixo" if score < 25 else "Médio" if score < 50 else "Alto" if score < 75 else "Crítico"


def resumo(eventos: list[dict]) -> dict:
    saidas_com_pii = [e for e in _saidas(eventos) if e.get("tipos")]
    todos_com_pii = [e for e in eventos if e.get("tipos")]
    por_tipo = Counter(t for e in todos_com_pii for t in e["tipos"])
    bloqueados = sum(1 for e in saidas_com_pii if e["bloqueado"])
    score = risco_cidadao(eventos)
    return {
        "score": score,
        "nivel": nivel(score),
        "por_tipo": dict(por_tipo),
        "bloqueados": bloqueados,
        "vazados": len(saidas_com_pii) - bloqueados,
        "entradas_marcadas": sum(1 for e in eventos if e.get("destino") == "entrada" and e.get("tipos")),
        "total_eventos": len(eventos),
    }
