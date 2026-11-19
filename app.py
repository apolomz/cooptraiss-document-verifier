"""
COOPTRAISS | Verificador documental
Prototipo académico de firma criptográfica y verificación de integridad documental.

Desarrollado para el proyecto de auditoría de seguridad de la información
del proceso de ahorro de COOPTRAISS - Universidad del Valle.
"""

from __future__ import annotations

import streamlit as st

from crypto.keys import generate_key_pair, serialize_public_key
from crypto.signer import calculate_sha256, sign_document
from utils.documents import (
    MAX_DOCUMENT_SIZE,
    VerificationResult,
    build_zip_package,
    create_manifest,
    sanitize_filename,
    verify_individual_files,
    verify_package,
)

# Configuración de página
st.set_page_config(
    page_title="COOPTRAISS | Verificador documental",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Inyección de estilos CSS profesionales y sobrios (sin dependencias externas)
st.markdown(
    """
    <style>
        /* Tipografía y espaciado base */
        .main-header {
            background: linear-gradient(135deg, #0f2b48 0%, #173f67 100%);
            color: #ffffff;
            padding: 2rem 2.5rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            border-left: 6px solid #0ea5e9;
        }
        .main-header h1 {
            color: #ffffff;
            font-size: 1.85rem;
            font-weight: 700;
            margin: 0 0 0.4rem 0;
            letter-spacing: -0.02em;
        }
        .main-header p.subtitle {
            color: #e2e8f0;
            font-size: 1rem;
            margin: 0 0 0.75rem 0;
            font-weight: 400;
        }
        .academic-badge {
            display: inline-block;
            background-color: rgba(14, 165, 233, 0.2);
            color: #bae6fd;
            border: 1px solid rgba(14, 165, 233, 0.4);
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.82rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .disclaimer-banner {
            background-color: #f8fafc;
            border: 1px solid #cbd5e1;
            border-left: 4px solid #f59e0b;
            padding: 0.85rem 1.25rem;
            border-radius: 6px;
            margin-bottom: 1.5rem;
            font-size: 0.88rem;
            color: #334155;
            line-height: 1.45;
        }
        .content-card {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 1.25rem 1.5rem;
            margin-bottom: 1.25rem;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.03);
        }
        .content-card h3 {
            color: #0f2b48;
            font-size: 1.15rem;
            font-weight: 600;
            margin-top: 0;
            margin-bottom: 0.75rem;
            border-bottom: 1px solid #f1f5f9;
            padding-bottom: 0.5rem;
        }
        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 0.35rem 0;
            border-bottom: 1px dashed #f1f5f9;
            font-size: 0.9rem;
        }
        .info-label {
            color: #64748b;
            font-weight: 500;
        }
        .info-value {
            color: #0f172a;
            font-weight: 600;
            text-align: right;
        }
        .hash-code {
            font-family: Consolas, "Liberation Mono", Menlo, Courier, monospace;
            background-color: #f1f5f9;
            color: #0f2b48;
            padding: 0.6rem 0.8rem;
            border-radius: 4px;
            border: 1px solid #cbd5e1;
            word-break: break-all;
            font-size: 0.85rem;
            margin: 0.5rem 0;
        }
        .result-box-valid {
            background-color: #f0fdf4;
            border: 1px solid #86efac;
            border-left: 5px solid #16a34a;
            color: #14532d;
            padding: 1.25rem;
            border-radius: 6px;
            margin: 1rem 0;
        }
        .result-box-invalid {
            background-color: #fef2f2;
            border: 1px solid #fca5a5;
            border-left: 5px solid #dc2626;
            color: #7f1d1d;
            padding: 1.25rem;
            border-radius: 6px;
            margin: 1rem 0;
        }
        .result-box-error {
            background-color: #fffbeb;
            border: 1px solid #fde68a;
            border-left: 5px solid #d97706;
            color: #78350f;
            padding: 1.25rem;
            border-radius: 6px;
            margin: 1rem 0;
        }
        .footer-text {
            color: #64748b;
            font-size: 0.82rem;
            text-align: center;
            padding: 1.5rem 0 0.5rem 0;
            border-top: 1px solid #e2e8f0;
            margin-top: 2rem;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# Encabezado institucional sobrio
st.markdown(
    """
    <div class="main-header">
        <span class="academic-badge">Universidad del Valle &bull; Ciberseguridad</span>
        <h1>COOPTRAISS | Verificador documental</h1>
        <p class="subtitle">Prototipo académico de firma criptográfica y verificación de integridad documental.</p>
    </div>
    <div class="disclaimer-banner">
        <strong>Aviso de alcance:</strong> Prototipo académico independiente desarrollado como soporte a la
        auditoría de seguridad de la información del proceso de ahorro de COOPTRAISS. No constituye un canal
        oficial de la cooperativa ni un servicio de firma digital certificada conforme a la Ley 527 de 1999.
    </div>
    """,
    unsafe_allow_html=True,
)


def format_file_size(size_bytes: int) -> str:
    """Formatea tamaños de bytes a unidades legibles."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    return f"{size_bytes / (1024 * 1024):.2f} MB"


def render_verification_view(result: VerificationResult):
    """Presenta el resultado de verificación con jerarquía profesional."""
    if result.status == "VALID":
        st.markdown(
            f"""
            <div class="result-box-valid">
                <h4 style="margin: 0 0 0.5rem 0; color: #166534; font-size: 1.15rem; font-weight: 700;">
                    Firma criptográfica válida
                </h4>
                <p style="margin: 0; font-size: 0.95rem; line-height: 1.45;">
                    {result.message}
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    elif result.status == "INVALID":
        st.markdown(
            f"""
            <div class="result-box-invalid">
                <h4 style="margin: 0 0 0.5rem 0; color: #991b1b; font-size: 1.15rem; font-weight: 700;">
                    Firma criptográfica inválida
                </h4>
                <p style="margin: 0; font-size: 0.95rem; line-height: 1.45;">
                    {result.message}
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:  # ERROR
        st.markdown(
            f"""
            <div class="result-box-error">
                <h4 style="margin: 0 0 0.5rem 0; color: #92400e; font-size: 1.15rem; font-weight: 700;">
                    Error de entrada o estructura de paquete
                </h4>
                <p style="margin: 0; font-size: 0.95rem; line-height: 1.45;">
                    {result.message}
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Panel de detalles técnicos de la verificación
    st.markdown("#### Detalle técnico de la verificación")
    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            f"""
            <div class="content-card">
                <h3>Parámetros de Integridad</h3>
                <div class="info-row">
                    <span class="info-label">Archivo analizado:</span>
                    <span class="info-value">{result.original_filename or 'documento_original.bin'}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Algoritmo de hash:</span>
                    <span class="info-value">SHA-256</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Coincidencia de hash:</span>
                    <span class="info-value">{'Conforme' if result.hash_match else 'Discrepancia detectada'}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Estado de la firma:</span>
                    <span class="info-value">{'Verificada matemáticamente' if result.signature_valid else 'No verificada / inviable'}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
            <div class="content-card">
                <h3>Criptografía Aplicada</h3>
                <div class="info-row">
                    <span class="info-label">Esquema de firma:</span>
                    <span class="info-value">{result.algorithm_info}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Mecanismo de relleno:</span>
                    <span class="info-value">PSS (MGF1 con SHA-256)</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Longitud de clave RSA:</span>
                    <span class="info-value">{result.key_size_bits} bits</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Modo de procesamiento:</span>
                    <span class="info-value">Memoria volátil (sin persistencia en disco)</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if result.document_sha256:
        st.markdown("**Hash SHA-256 calculado del documento analizado:**")
        st.markdown(f'<div class="hash-code">{result.document_sha256}</div>', unsafe_allow_html=True)

    if result.manifest_sha256 and result.manifest_sha256 != result.document_sha256:
        st.markdown("**Hash SHA-256 registrado en el manifiesto:**")
        st.markdown(f'<div class="hash-code">{result.manifest_sha256}</div>', unsafe_allow_html=True)

    # Explicación técnica y limitaciones
    st.info(
        "Nota técnica sobre identidad y confianza: La validez matemática de la firma confirma que "
        "el documento no ha sido modificado y que fue emitido con la clave privada correspondiente "
        "a la clave pública provista. Sin embargo, no acredita por sí sola la identidad de una persona "
        "o entidad jurídica, ya que este prototipo no incorpora certificados X.509 de una Autoridad "
        "Certificadora (CA) acreditada ni sellos de tiempo confiables. La clave pública debe obtenerse "
        "siempre a través de un canal confiable e independiente."
    )


# ==============================================================================
# NAVEGACIÓN PRINCIPAL
# ==============================================================================

tab_firmar, tab_verificar = st.tabs(["Firmar documento", "Verificar documento"])

# ==============================================================================
# MÓDULO A: FIRMAR DOCUMENTO
# ==============================================================================

with tab_firmar:
    st.markdown("### Generación de firma criptográfica")
    st.write(
        "Cargue un documento para calcular su huella digital criptográfica (SHA-256), "
        "generar un par de claves RSA de 3072 bits y emitir una firma digital mediante el "
        "esquema probabilístico RSA-PSS."
    )

    st.warning(
        "Advertencia de confidencialidad: No utilice documentos reales de asociados, datos financieros "
        "confidenciales ni información personal reservada para esta demostración. Puede utilizar el "
        "archivo demostrativo ubicado en 'examples/certificado_cdat_demo.txt'."
    )

    archivo_a_firmar = st.file_uploader(
        "Seleccione el documento a firmar (PDF, DOCX, TXT, PNG, JPG u otros formatos, máx. 20 MB)",
        key="uploader_firmar",
        help="El archivo se procesará exclusivamente en memoria sin guardarse en el servidor.",
    )

    if archivo_a_firmar is not None:
        nombre_original = archivo_a_firmar.name
        tamano_bytes = len(archivo_a_firmar.getvalue())
        tipo_mime = archivo_a_firmar.type or "application/octet-stream"
        extension = nombre_original.split(".")[-1].upper() if "." in nombre_original else "BIN"

        col_meta1, col_meta2, col_meta3 = st.columns(3)
        with col_meta1:
            st.metric("Nombre del archivo", sanitize_filename(nombre_original))
        with col_meta2:
            st.metric("Formato detectado", extension)
        with col_meta3:
            st.metric("Tamaño", format_file_size(tamano_bytes))

        # Validación temprana de tamaño
        if tamano_bytes == 0:
            st.error("El archivo seleccionado está vacío (0 bytes). Seleccione un archivo con contenido.")
        elif tamano_bytes > MAX_DOCUMENT_SIZE:
            st.error(
                f"El archivo seleccionado ({format_file_size(tamano_bytes)}) supera el límite "
                f"máximo permitido de 20 MB."
            )
        else:
            if st.button("Generar firma criptográfica", type="primary", key="btn_generar_firma"):
                with st.spinner("Calculando hash SHA-256 y generando firma RSA-PSS (3072 bits)..."):
                    try:
                        document_bytes = archivo_a_firmar.getvalue()
                        clean_filename = sanitize_filename(nombre_original)

                        # 1. Calcular hash SHA-256
                        sha256_hash = calculate_sha256(document_bytes)

                        # 2. Generar par de claves RSA en memoria
                        private_key, public_key = generate_key_pair(key_size=3072)

                        # 3. Firmar con RSA-PSS y SHA-256
                        signature_bytes = sign_document(document_bytes, private_key)

                        # 4. Serializar clave pública a formato PEM
                        public_key_pem = serialize_public_key(public_key)

                        # 5. Generar manifiesto
                        manifest_dict = create_manifest(
                            original_filename=clean_filename,
                            document_bytes=document_bytes,
                            key_size_bits=3072,
                        )

                        # 6. Construir paquete ZIP en memoria
                        zip_package_bytes = build_zip_package(
                            document_bytes=document_bytes,
                            signature_bytes=signature_bytes,
                            public_key_pem=public_key_pem,
                            manifest=manifest_dict,
                        )

                        # Descartar explícitamente la clave privada de memoria
                        del private_key

                        # Guardar estado para persistir la descarga
                        st.session_state["firma_generada"] = {
                            "filename": clean_filename,
                            "sha256": sha256_hash,
                            "doc_size": tamano_bytes,
                            "zip_bytes": zip_package_bytes,
                        }

                    except Exception as exc:  # pylint: disable=broad-except
                        st.error(f"Error durante el proceso de firma: {exc}")

            # Mostrar resultados si la firma ya fue generada
            if "firma_generada" in st.session_state and st.session_state["firma_generada"].get("filename") == sanitize_filename(nombre_original):
                res_info = st.session_state["firma_generada"]

                st.success("Firma criptográfica generada exitosamente.")

                col_res1, col_res2 = st.columns(2)
                with col_res1:
                    st.markdown(
                        f"""
                        <div class="content-card">
                            <h3>Parámetros Documentales</h3>
                            <div class="info-row">
                                <span class="info-label">Archivo firmado:</span>
                                <span class="info-value">{res_info['filename']}</span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">Tamaño del documento:</span>
                                <span class="info-value">{format_file_size(res_info['doc_size'])}</span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">Algoritmo de hash:</span>
                                <span class="info-value">SHA-256</span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">Estado de la operación:</span>
                                <span class="info-value">Completada exitosamente</span>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                with col_res2:
                    st.markdown(
                        """
                        <div class="content-card">
                            <h3>Especificación Criptográfica</h3>
                            <div class="info-row">
                                <span class="info-label">Algoritmo de firma:</span>
                                <span class="info-value">RSA-PSS</span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">Tamaño de clave RSA:</span>
                                <span class="info-value">3072 bits</span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">Función de máscara:</span>
                                <span class="info-value">MGF1 con SHA-256</span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">Longitud de salt:</span>
                                <span class="info-value">PSS.MAX_LENGTH</span>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                st.markdown("**Hash SHA-256 completo del documento:**")
                st.markdown(f'<div class="hash-code">{res_info["sha256"]}</div>', unsafe_allow_html=True)

                st.markdown("#### Descarga del paquete de verificación")
                st.write(
                    "El paquete descargable contiene: `documento_original.bin`, `firma.sig`, "
                    "`clave_publica.pem` y `manifest.json`. La clave privada fue utilizada exclusivamente "
                    "en memoria volátil y destruida de forma inmediata, por lo cual no forma parte del paquete."
                )

                zip_download_name = f"paquete_firma_{res_info['filename']}.zip"
                st.download_button(
                    label="Descargar paquete de verificación (ZIP)",
                    data=res_info["zip_bytes"],
                    file_name=zip_download_name,
                    mime="application/zip",
                    type="primary",
                    key="btn_descargar_zip",
                )


# ==============================================================================
# MÓDULO B: VERIFICAR DOCUMENTO
# ==============================================================================

with tab_verificar:
    st.markdown("### Verificación de firma e integridad")
    st.write(
        "Seleccione la modalidad de verificación: paquete ZIP completo (recomendado para auditoría) "
        "o carga individual del documento, su archivo de firma (.sig) y su clave pública (.pem)."
    )

    modalidad = st.radio(
        "Modalidad de verificación:",
        options=["Paquete ZIP completo", "Archivos individuales"],
        horizontal=True,
        key="radio_modalidad",
    )

    if modalidad == "Paquete ZIP completo":
        st.markdown("#### Modalidad 1: Verificación mediante paquete ZIP")
        st.write(
            "Cargue el archivo ZIP generado en el módulo de firma. El sistema validará su estructura, "
            "comprobará la integridad contra el manifiesto y verificará la firma criptográfica en memoria."
        )

        archivo_zip = st.file_uploader(
            "Seleccione el paquete ZIP de verificación",
            type=["zip"],
            key="uploader_zip",
            help="El paquete debe contener documento_original.bin, firma.sig, clave_publica.pem y manifest.json.",
        )

        if archivo_zip is not None:
            col_zip1, col_zip2 = st.columns(2)
            with col_zip1:
                st.metric("Archivo", archivo_zip.name)
            with col_zip2:
                st.metric("Tamaño del paquete", format_file_size(len(archivo_zip.getvalue())))

            if st.button("Verificar firma del paquete", type="primary", key="btn_verif_zip"):
                with st.spinner("Inspeccionando paquete y verificando firma criptográfica..."):
                    zip_bytes = archivo_zip.getvalue()
                    resultado = verify_package(zip_bytes)
                    st.session_state["resultado_verificacion_zip"] = resultado

        if "resultado_verificacion_zip" in st.session_state:
            render_verification_view(st.session_state["resultado_verificacion_zip"])

    else:
        st.markdown("#### Modalidad 2: Verificación mediante archivos individuales")
        st.write(
            "Cargue por separado el documento original, su archivo de firma criptográfica (.sig) "
            "y la clave pública del firmante (.pem)."
        )

        col_ind1, col_ind2, col_ind3 = st.columns(3)

        with col_ind1:
            archivo_doc_ind = st.file_uploader(
                "1. Documento original",
                key="uploader_doc_ind",
                help="El archivo tal y como fue firmado originalmente.",
            )

        with col_ind2:
            archivo_sig_ind = st.file_uploader(
                "2. Archivo de firma (.sig)",
                type=["sig", "bin"],
                key="uploader_sig_ind",
                help="Firma criptográfica binaria generada con RSA-PSS.",
            )

        with col_ind3:
            archivo_pem_ind = st.file_uploader(
                "3. Clave pública (.pem)",
                type=["pem", "key", "txt"],
                key="uploader_pem_ind",
                help="Clave pública RSA en formato PEM SubjectPublicKeyInfo.",
            )

        if archivo_doc_ind and archivo_sig_ind and archivo_pem_ind:
            if st.button("Verificar firma individual", type="primary", key="btn_verif_indiv"):
                with st.spinner("Comprobando integridad y verificando firma..."):
                    doc_bytes = archivo_doc_ind.getvalue()
                    sig_bytes = archivo_sig_ind.getvalue()
                    pem_bytes = archivo_pem_ind.getvalue()

                    resultado = verify_individual_files(
                        document_bytes=doc_bytes,
                        signature_bytes=sig_bytes,
                        public_key_pem=pem_bytes,
                        original_filename=archivo_doc_ind.name,
                    )
                    st.session_state["resultado_verificacion_indiv"] = resultado

        if "resultado_verificacion_indiv" in st.session_state:
            render_verification_view(st.session_state["resultado_verificacion_indiv"])

# Pie de página académico sobrio
st.markdown(
    """
    <div class="footer-text">
        <strong>COOPTRAISS | Verificador documental</strong> &bull; Prototipo académico de ciberseguridad<br>
        Universidad del Valle &bull; Auditoría de Seguridad de la Información del Proceso de Ahorro<br>
        Tecnologías: Python 3.13, Cryptography (RSA-PSS 3072 bits, SHA-256), Streamlit.
    </div>
    """,
    unsafe_allow_html=True,
)
