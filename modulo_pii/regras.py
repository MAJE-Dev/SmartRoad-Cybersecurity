"""Regras de detecção de PII. Cada regra: tipo -> (regex, descrição).

Para adicionar um novo tipo de dado sensível, basta incluir uma entrada aqui
(e, se precisar de validação extra, tratar em detector.py).
"""

REGRAS = {
    "CPF": (
        r"(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)",
        "CPF (11 dígitos). Com pontuação (###.###.###-##) é aceito sempre; sem pontuação, só se o dígito verificador bater.",
    ),
    "RG": (
        r"(?i)(?:\brg\b[\s:.nº°-]{0,6}\d{1,2}\.?\d{3}\.?\d{3}-?[\dx]|(?<!\d)\d{1,2}\.\d{3}\.\d{3}-[\dx](?![\d]))",
        "RG: com a palavra 'RG' antes (ex.: RG: 12.345.678-9) ou no formato ##.###.###-X.",
    ),
    "SENHA": (
        r"(?i)\b(?:senha|password|pwd|passwd)\b\s*(?:[:=]|é|eh|is)\s*\S+",
        "Credencial em texto: 'senha: xxx', 'password=xxx', 'senha é xxx'.",
    ),
    "SAUDE": (
        r"(?i)\b(?:laudos?\s+m[ée]dicos?|atestados?\s+m[ée]dicos?|receitas?\s+m[ée]dicas?|"
        r"exames?\s+m[ée]dicos?|dados?\s+de\s+sa[úu]de|"
        r"diagn[óo]stico|prontu[áa]rio|cid[- ]?[a-z]\d{2}|hiv|diabetes|c[âa]ncer|"
        r"cadeirante|cadeira de rodas|defici[êe]ncia|baixa vis[ãa]o|cegueira|surdez|"
        r"mobilidade reduzida|autismo|alzheimer|epilepsia)\b",
        "Dado de saúde (laudo, atestado, diagnóstico...) ou perfil de mobilidade/deficiência (dado sensível, LGPD art. 5º, II).",
    ),
    "EMAIL": (
        r"[\w.+-]+@[\w-]+\.[\w.-]+",
        "Endereço de e-mail.",
    ),
    "TELEFONE": (
        r"(?<!\d)(?:\+?55\s?)?\(?\d{2}\)?\s?9?\d{4}-?\d{4}(?!\d)",
        "Telefone brasileiro (fixo ou celular).",
    ),
}

# Gravidade base de cada tipo (usada no indicador de Risco Cidadão e no alerta da IA)
PESO = {"SENHA": 40, "SAUDE": 30, "CPF": 20, "RG": 20, "TELEFONE": 8, "EMAIL": 5}
