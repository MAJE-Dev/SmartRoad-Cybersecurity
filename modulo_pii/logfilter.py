"""Proteção do logging padrão do Python: bloqueia PII mesmo em logger.info(...) direto.

Os sinks (sink_log) protegem quem os usa. Aqui protegemos TODO log da aplicação: toda
mensagem criada passa por uma fábrica de registros que verifica o rótulo de taint dos argumentos e
roda o detector de PII no texto final. Se achar dado sensível, troca a mensagem por um aviso e audita.
"""
import logging

from .auditoria import registrar_auditoria
from .detector import detectar_pii
from .taint import tags_de

MENSAGEM = "[LOG BLOQUEADO: dado pessoal detectado]"
_instalado = False


def instalar_protecao_logging() -> None:
    global _instalado
    if _instalado:
        return
    fabrica_original = logging.getLogRecordFactory()

    def fabrica(*args, **kwargs):
        registro = fabrica_original(*args, **kwargs)
        try:
            texto = registro.getMessage()
        except Exception:  # mensagem malformada: não interferir
            return registro
        tipos = set(tags_de(registro.args)) if registro.args else set()
        if isinstance(registro.msg, str):
            tipos |= tags_de(registro.msg)
        tipos |= {a.tipo for a in detectar_pii(texto)}
        if tipos:
            registrar_auditoria(registro.name, "log", list(tipos), True, "logging bloqueado")
            registro.msg, registro.args = MENSAGEM, ()
        return registro

    logging.setLogRecordFactory(fabrica)
    _instalado = True
