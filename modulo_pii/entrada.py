"""Interceptação da ENTRADA: marca (taint) campos sensíveis de um payload JSON.

Dois critérios, combinados:
  1) pelo NOME da chave  (ex.: {"documento": "...", "senha": "..."})
  2) pelo VALOR          (o detector de PII roda no conteúdo de qualquer campo de texto)

Retorna uma cópia do payload em que os valores sensíveis viram `Tainted` (com as tags) e a lista
dos campos marcados. Só nomes de campos e tipos são registrados; o valor nunca vai para log.
"""
import unicodedata

from .detector import detectar_pii
from .taint import Tainted

CHAVES_SENSIVEIS = {
    "cpf": "CPF", "documento": "CPF", "doc": "CPF",
    "rg": "RG",
    "senha": "SENHA", "password": "SENHA", "pwd": "SENHA", "passwd": "SENHA",
    "laudo": "SAUDE", "saude": "SAUDE", "dados_de_saude": "SAUDE", "dados_saude": "SAUDE",
    "diagnostico": "SAUDE", "prontuario": "SAUDE", "perfil_mobilidade": "SAUDE",
    "email": "EMAIL", "e_mail": "EMAIL",
    "telefone": "TELEFONE", "celular": "TELEFONE", "fone": "TELEFONE",
}
VALORES_NEUTROS = {"", "nenhum", "none", "null"}


def _normalizar(chave: str) -> str:
    sem_acento = "".join(c for c in unicodedata.normalize("NFD", str(chave)) if unicodedata.category(c) != "Mn")
    return sem_acento.lower().strip().replace("-", "_").replace(" ", "_")


def _marcar_escalar(chave, valor, caminho, campos):
    if not isinstance(valor, (str, int)) or isinstance(valor, bool):
        return valor
    texto = str(valor)
    tipos = {a.tipo for a in detectar_pii(texto)}
    tipo_chave = CHAVES_SENSIVEIS.get(_normalizar(chave)) if chave is not None else None
    if tipo_chave and texto.strip().lower() not in VALORES_NEUTROS:
        tipos.add(tipo_chave)
    if not tipos:
        return valor
    campos.append((caminho, sorted(tipos)))
    return Tainted(texto, tipos)


def _percorrer(valor, chave, caminho, campos):
    if isinstance(valor, dict):
        return {k: _percorrer(v, k, f"{caminho}.{k}" if caminho else str(k), campos) for k, v in valor.items()}
    if isinstance(valor, list):
        return [_percorrer(v, chave, f"{caminho}[{i}]", campos) for i, v in enumerate(valor)]
    return _marcar_escalar(chave, valor, caminho, campos)


def marcar_payload(dados):
    """Retorna (payload_marcado, [(caminho_do_campo, [tipos])...])."""
    campos: list = []
    return _percorrer(dados, None, "", campos), campos
