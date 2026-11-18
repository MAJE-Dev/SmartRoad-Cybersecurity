"""Dashboard Executivo: Risco Cidadão. Rode com: streamlit run dashboard/painel.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import streamlit as st

from ia.tradutor import traduzir_alerta
from modulo_pii.auditoria import ler_eventos
from modulo_pii.risco import resumo

st.set_page_config(page_title="SmartRoad · Risco Cidadão", page_icon="🛡️", layout="wide")
st.title("🛡️ SmartRoad · Risco Cidadão")
st.caption("Monitoramento de dados pessoais (PII) · Cybersecurity GS 2026.2 · dados simulados")

if st.button("🔄 Atualizar"):
    st.rerun()

eventos = ler_eventos()
r = resumo(eventos)

# Farol de risco: verde (Baixo) · amarelo (Médio) · vermelho (Alto/Crítico)
FAROL = {"Baixo": 0, "Médio": 1, "Alto": 2, "Crítico": 2}
CORES = ["#2ecc71", "#f1c40f", "#e74c3c"]
ROTULO = {0: "Risco BAIXO", 1: "Risco MÉDIO", 2: "Risco ALTO"}


def farol_html(nivel: str) -> str:
    ativo = FAROL[nivel]
    bolas = ""
    for i, cor in enumerate(CORES):
        fundo = cor if i == ativo else "#3a3a3a"
        brilho = f"0 0 18px {cor}" if i == ativo else "none"
        bolas += (f'<span style="display:inline-block;width:44px;height:44px;border-radius:50%;'
                  f'margin-right:12px;background:{fundo};box-shadow:{brilho}"></span>')
    return (f'<div style="font-size:14px;opacity:.7;margin-bottom:6px">Farol de risco</div>'
            f'<div>{bolas}</div>'
            f'<div style="margin-top:8px;font-weight:700;color:{CORES[ativo]}">{ROTULO[ativo]} · {nivel}</div>')


c0, c1, c2, c3, c4, c5 = st.columns([1.6, 1, 1, 1, 1, 1])
c0.markdown(farol_html(r["nivel"]), unsafe_allow_html=True)
c1.metric("Risco Cidadão", f"{r['score']}/100")
c2.metric("Vazamentos bloqueados", r["bloqueados"])
c3.metric("Vazamentos ocorridos", r["vazados"])
c4.metric("Campos marcados na entrada", r["entradas_marcadas"])
c5.metric("Eventos auditados", r["total_eventos"])
st.progress(r["score"] / 100)

esq, dir_ = st.columns(2)
with esq:
    st.subheader("PII detectada por tipo")
    if r["por_tipo"]:
        st.bar_chart(pd.Series(r["por_tipo"], name="ocorrências"))
    else:
        st.info("Nenhuma PII detectada ainda. Rode `python scripts/cenarios_demo.py`.")
with dir_:
    st.subheader("Último alerta (traduzido para o cidadão)")
    com_pii = [e for e in eventos if e.get("tipos") and e.get("destino") != "entrada"]
    if com_pii:
        ultimo = com_pii[-1]
        alerta = traduzir_alerta(ultimo)
        st.warning(alerta["texto"])
        st.caption(f"Origem do texto: {'IA' if alerta['fonte'] == 'llm' else 'texto fixo (fallback)'} · "
                   f"destino: {ultimo['destino']} · {'bloqueado' if ultimo['bloqueado'] else 'NÃO bloqueado'}")
    else:
        st.success("Sem alertas.")

st.subheader("Trilha de auditoria (sem dados sensíveis)")
somente_pii = st.checkbox("Mostrar só eventos com dado pessoal", value=True)
if eventos:
    df = pd.DataFrame(eventos[::-1])
    if somente_pii:
        df = df[df["tipos"].map(bool)]
    st.dataframe(df.head(50), use_container_width=True, hide_index=True)
