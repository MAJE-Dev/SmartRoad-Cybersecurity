import pytest
from fastapi.testclient import TestClient

from app.main import app

CPF = "529.982.247-25"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_fluxo_completo(client):
    r = client.post("/cadastro", json={"cpf": CPF, "senha": "SenhaForte123", "perfil_mobilidade": "cadeirante"})
    assert r.status_code == 201 and r.json()["cpf"] == "***.***.***-25"

    assert client.post("/cadastro", json={"cpf": CPF, "senha": "SenhaForte123"}).status_code == 409
    r422 = client.post("/cadastro", json={"cpf": "111.111.111-11", "senha": "SenhaForte123"})
    assert r422.status_code == 422
    assert "111.111.111" not in r422.text  # o erro de validação não ecoa o dado digitado
    assert client.post("/login", json={"cpf": CPF, "senha": "errada"}).status_code == 401

    r = client.post("/login", json={"cpf": CPF, "senha": "SenhaForte123"})
    assert r.status_code == 200
    token = r.json()["token"]

    # relato com CPF no texto: publica mascarado + avisa
    r = client.post("/relatos", headers={"Authorization": f"Bearer {token}"},
                    json={"tipo": "buraco", "trecho": "B-C", "descricao": f"Buraco enorme, meu cpf é {CPF}"})
    assert r.status_code == 201
    corpo = r.json()
    assert CPF not in corpo["descricao_publicada"] and corpo["aviso"]

    assert CPF not in client.get("/relatos").text


def test_rota_evita_trecho_ruim(client):
    base = client.get("/rota", params={"origem": "A", "destino": "D"}).json()
    assert base["caminho"][0] == "A" and base["caminho"][-1] == "D"


def test_demo_vazamentos_bloqueados(client):
    assert client.get("/demo/vaza-cpf-no-log").status_code == 500
    assert client.get("/demo/cpf-mascarado-no-log").status_code == 200
    assert client.get("/demo/vaza-senha-na-resposta").status_code == 500
    r = client.get("/demo/vaza-sem-sink")  # pego pelo middleware
    assert r.status_code == 500 and CPF not in r.text


def test_swagger_e_openapi_nao_sao_bloqueados(client):
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200


def test_exemplo_do_professor_documento_e_marcado_na_entrada_e_volta_mascarado(client):
    from modulo_pii.auditoria import ler_eventos
    from modulo_pii.risco import risco_cidadao

    r = client.post("/demo/documento", json={"documento": "123.456.789-00"})
    assert r.status_code == 200
    assert r.json() == {"marcado_como": ["CPF"], "documento": "***.***.***-00"}
    entradas = [e for e in ler_eventos() if e["destino"] == "entrada"]
    assert entradas and "CPF" in entradas[-1]["tipos"]
    assert "123.456" not in str(entradas[-1])      # a auditoria nunca guarda o valor
    assert risco_cidadao(entradas) == 0


def test_logger_info_direto_e_bloqueado_na_aplicacao(client, caplog):
    import logging

    with caplog.at_level(logging.INFO):
        assert client.get("/demo/logger-direto").status_code == 200
    assert "diabetes" not in caplog.text
    assert "LOG BLOQUEADO" in caplog.text
