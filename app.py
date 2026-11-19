
import streamlit as st

st.set_page_config(
    page_title="COOPTRAISS | Verificador documental",
    page_icon="🔐",
    layout="wide"
)

st.title("COOPTRAISS | Verificador documental")

st.write(
    "Prototipo académico para la generación y verificación "
    "de firmas criptográficas en documentos."
)

st.divider()

st.subheader("Panel principal")

col1, col2 = st.columns(2)

with col1:
    st.markdown("### Firmar documento")
    st.write(
        "Genera una firma criptográfica para comprobar "
        "posteriormente la integridad y autenticidad del documento."
    )
    st.info("Módulo en construcción.")

with col2:
    st.markdown("### Verificar documento")
    st.write(
        "Comprueba la validez de una firma utilizando "
        "la clave pública correspondiente."
    )
    st.info("Módulo en construcción.")

st.divider()

st.caption(
    "Proyecto de auditoría de seguridad de la información "
    "del proceso de ahorro de COOPTRAISS."
)
