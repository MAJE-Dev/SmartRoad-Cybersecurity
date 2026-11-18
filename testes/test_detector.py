from modulo_pii.detector import detectar_pii
from modulo_pii.sanitizers import mascarar_cpf, sanitizar_texto


def tipos(txt):
    return {a.tipo for a in detectar_pii(txt)}


def test_cpf_com_e_sem_pontuacao():
    assert "CPF" in tipos("meu cpf 529.982.247-25")
    assert "CPF" in tipos("cpf 52998224725 ok")


def test_cpf_com_pontuacao_e_detectado_mesmo_com_digito_invalido():
    # exemplo do PDF do professor: 123.456.789-00 (dígito verificador inválido)
    assert "CPF" in tipos("documento: 123.456.789-00")


def test_numero_de_11_digitos_sem_pontuacao_e_digito_invalido_nao_e_cpf():
    assert "CPF" not in tipos("protocolo 12345678900")


def test_numero_longo_nao_vira_cpf():
    assert "CPF" not in tipos("pedido 1529982247259")


def test_senha():
    assert "SENHA" in tipos("minha senha: abc12345")
    assert "SENHA" in tipos("password=xyz")


def test_senha_em_frase_normal_nao_dispara():
    assert "SENHA" not in tipos("a senha do portão quebrou")


def test_saude_e_mobilidade():
    assert "SAUDE" in tipos("sou cadeirante e a calçada não tem rampa")
    assert "SAUDE" in tipos("diagnóstico de diabetes")


def test_texto_normal_sem_pii():
    assert tipos("Buraco grande na calçada em frente à padaria") == set()


def test_email_e_telefone():
    assert "EMAIL" in tipos("fale com ana@exemplo.com")
    assert "TELEFONE" in tipos("ligue (11) 91234-5678")


def test_sanitizar_remove_pii():
    limpo, achados = sanitizar_texto("buraco na rua, meu cpf 529.982.247-25")
    assert "529.982.247-25" not in limpo
    assert "***.***.***-25" in limpo
    assert achados


def test_mascara_cpf():
    assert mascarar_cpf("529.982.247-25") == "***.***.***-25"


def test_achado_publico_sem_trecho():
    a = detectar_pii("cpf 529.982.247-25")[0]
    assert "trecho" not in a.publico()


def test_nenhuma_mascara_e_redetectada_como_pii():
    """A máscara não pode disparar o próprio detector (senão o sink bloqueia a resposta já sanitizada)."""
    from modulo_pii.sanitizers import mascarar_generico

    for tipo in ("CPF", "RG", "SENHA", "EMAIL", "SAUDE", "TELEFONE", "OUTRO"):
        assert detectar_pii(mascarar_generico("529.982.247-25", tipo)) == [], tipo


def test_texto_sanitizado_completo_nao_tem_pii():
    limpo, achados = sanitizar_texto("Buraco grande, sou cadeirante. Meu cpf é 529.982.247-25, RG: 12.345.678-9")
    assert achados and detectar_pii(limpo) == []
