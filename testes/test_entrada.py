import logging

from modulo_pii.detector import detectar_pii
from modulo_pii.entrada import marcar_payload
from modulo_pii.logfilter import MENSAGEM, instalar_protecao_logging
from modulo_pii.taint import Tainted


def tipos(txt):
    return {a.tipo for a in detectar_pii(txt)}


def test_rg():
    assert "RG" in tipos("RG: 12.345.678-9")
    assert "RG" in tipos("meu rg 123456789")
    assert "RG" in tipos("12.345.678-X")
    assert "RG" not in tipos("pedido número 12345")


def test_rg_nao_confunde_com_cpf():
    assert tipos("cpf 529.982.247-25") == {"CPF"}


def test_laudo_e_atestado_medico():
    assert "SAUDE" in tipos("laudo médico: paciente com asma")
    assert "SAUDE" in tipos("atestado médico anexado")
    assert "SAUDE" not in tipos("o laudo técnico da obra saiu")


def test_marcar_payload_por_chave_e_por_valor():
    dados = {
        "documento": "123.456.789-00",
        "senha": "abc12345",
        "nome": "Ana",
        "obs": "fale comigo em ana@exemplo.com",
        "aninhado": {"rg": "12.345.678-9"},
        "lista": ["ok", "cpf 529.982.247-25"],
    }
    novo, campos = marcar_payload(dados)
    mapa = dict(campos)
    assert "CPF" in mapa["documento"] and "SENHA" in mapa["senha"]
    assert "EMAIL" in mapa["obs"] and "RG" in mapa["aninhado.rg"] and "CPF" in mapa["lista[1]"]
    assert "nome" not in mapa and "lista[0]" not in mapa
    assert isinstance(novo["documento"], Tainted) and "CPF" in novo["documento"].tags
    assert novo["nome"] == "Ana" and not isinstance(novo["nome"], Tainted)


def test_chave_sensivel_com_valor_neutro_nao_marca():
    _, campos = marcar_payload({"perfil_mobilidade": "nenhum", "senha": ""})
    assert campos == []


def test_chave_com_acento_e_caixa():
    _, campos = marcar_payload({"Diagnóstico": "gripe", "E-mail": "x"})
    assert {c for c, _ in campos} == {"Diagnóstico", "E-mail"}


def test_logger_info_com_valor_sensivel_e_bloqueado(caplog):
    instalar_protecao_logging()
    with caplog.at_level(logging.INFO):
        logging.getLogger("teste").info("dados_de_saude=%s", "laudo médico: diabetes")
        logging.getLogger("teste").info("senha: abc123")
        logging.getLogger("teste").info("mensagem normal sem dado pessoal")
    assert "diabetes" not in caplog.text and "abc123" not in caplog.text
    assert caplog.text.count(MENSAGEM) == 2
    assert "mensagem normal sem dado pessoal" in caplog.text


def test_logger_com_argumento_tainted_e_bloqueado(caplog):
    instalar_protecao_logging()
    with caplog.at_level(logging.INFO):
        logging.getLogger("teste").info("valor: %s", Tainted("qualquer texto", {"SAUDE"}))
    assert "qualquer texto" not in caplog.text and MENSAGEM in caplog.text
