"""
Pruebas automatizadas de la suite criptográfica y del motor documental.

Cubre las 16 pruebas obligatorias requeridas para la auditoría académica:
1. test_valid_signature: Firma válida con RSA-PSS y SHA-256.
2. test_modified_document_fails: Modificación mínima invalida la firma.
3. test_wrong_public_key_fails: Clave pública incorrecta no verifica la firma.
4. test_public_key_serialization: Serialización y carga PEM de clave pública RSA.
5. test_sha256_length: Longitud hexadecimal y determinismo de SHA-256.
6. test_empty_document_fails: Rechazo de firma de documentos vacíos.
7. test_zip_package_creation: Creación correcta del paquete ZIP con los 4 archivos.
8. test_zip_package_reading: Lectura y deserialización correcta del paquete en memoria.
9. test_verify_package_valid: Verificación exitosa de un paquete íntegro.
10. test_verify_package_modified_document: Detección de alteración del documento en paquete.
11. test_corrupted_signature: Detección de firma corrupta o truncada.
12. test_invalid_public_key: Manejo de claves PEM inválidas o corruptas.
13. test_corrupted_manifest: Manejo de manifiestos con JSON inválido o campos faltantes.
14. test_invalid_zip_file: Rechazo de archivos ZIP corruptos o con formato erróneo.
15. test_zip_duplicate_or_unexpected_entries: Prevención de entradas duplicadas y Zip Slip.
16. test_document_size_validation: Validación de límites de tamaño (vacío y > 20 MB).
"""

import io
import json
import warnings
import zipfile

import pytest

from crypto.keys import generate_key_pair, load_public_key, serialize_public_key
from crypto.signer import calculate_sha256, sign_document
from crypto.verifier import verify_signature
from utils.documents import (
    MAX_DOCUMENT_SIZE,
    PackageValidationError,
    build_zip_package,
    create_manifest,
    read_and_validate_zip_package,
    sanitize_filename,
    validate_document_size,
    verify_individual_files,
    verify_package,
)


@pytest.fixture(scope="module")
def key_pair():
    """Genera un par de claves RSA de 3072 bits para las pruebas del módulo."""
    return generate_key_pair(key_size=3072)


# ==============================================================================
# 1. PRUEBAS CRIPTOGRÁFICAS BÁSICAS (1-6)
# ==============================================================================

def test_valid_signature(key_pair):
    """1. Una firma criptográfica válida debe verificarse correctamente."""
    private_key, public_key = key_pair
    document = b"Certificado CDAT de prueba - COOPTRAISS"

    signature = sign_document(document, private_key)

    assert verify_signature(document, signature, public_key) is True


def test_modified_document_fails(key_pair):
    """2. Una modificación mínima del documento debe invalidar la firma."""
    private_key, public_key = key_pair
    original_document = b"Certificado CDAT de prueba - COOPTRAISS"

    signature = sign_document(original_document, private_key)

    # Modificación de un solo carácter
    modified_document = b"Certificado CDAT de prueba - COOPTRAISX"

    assert verify_signature(modified_document, signature, public_key) is False


def test_wrong_public_key_fails(key_pair):
    """3. Una clave pública diferente no debe validar la firma."""
    private_key, _ = key_pair
    _, wrong_public_key = generate_key_pair(key_size=3072)

    document = b"Documento de prueba - Proceso de Ahorro"

    signature = sign_document(document, private_key)

    assert verify_signature(document, signature, wrong_public_key) is False


def test_public_key_serialization(key_pair):
    """4. La clave pública debe poder exportarse a PEM y recargarse con idéntico comportamiento."""
    _, public_key = key_pair

    public_key_pem = serialize_public_key(public_key)
    loaded_public_key = load_public_key(public_key_pem)

    assert loaded_public_key.key_size == public_key.key_size
    assert serialize_public_key(loaded_public_key) == public_key_pem


def test_sha256_length():
    """5. SHA-256 debe producir un hash hexadecimal de exactamente 64 caracteres."""
    document = b"Documento de auditoria de ahorro COOPTRAISS"

    digest = calculate_sha256(document)

    assert len(digest) == 64
    assert all(c in "0123456789abcdefABCDEF" for c in digest)


def test_empty_document_fails(key_pair):
    """6. No debe permitirse firmar documentos vacíos."""
    private_key, _ = key_pair

    with pytest.raises(ValueError, match="vacío"):
        sign_document(b"", private_key)


# ==============================================================================
# 2. PRUEBAS DE EMPAQUETADO Y LECTURA ZIP (7-8)
# ==============================================================================

def test_zip_package_creation(key_pair):
    """7. El paquete ZIP debe construirse en memoria con los 4 archivos requeridos."""
    private_key, public_key = key_pair
    doc = b"Contenido de prueba para empaquetado CDAT"
    sig = sign_document(doc, private_key)
    pub_pem = serialize_public_key(public_key)
    manifest = create_manifest("cdat_demo.txt", doc, 3072)

    zip_bytes = build_zip_package(doc, sig, pub_pem, manifest)

    assert isinstance(zip_bytes, bytes)
    assert len(zip_bytes) > 0

    # Comprobar contenido del ZIP
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        file_list = zf.namelist()
        assert set(file_list) == {
            "documento_original.bin",
            "firma.sig",
            "clave_publica.pem",
            "manifest.json",
        }
        assert zf.read("documento_original.bin") == doc
        assert zf.read("firma.sig") == sig
        assert zf.read("clave_publica.pem") == pub_pem


def test_zip_package_reading(key_pair):
    """8. La lectura del paquete debe recuperar fielmente los 4 componentes."""
    private_key, public_key = key_pair
    doc = b"Lectura y validacion de paquete"
    sig = sign_document(doc, private_key)
    pub_pem = serialize_public_key(public_key)
    manifest = create_manifest("cdat_lectura.txt", doc, 3072)

    zip_bytes = build_zip_package(doc, sig, pub_pem, manifest)
    read_doc, read_sig, read_pub_pem, read_manifest = read_and_validate_zip_package(zip_bytes)

    assert read_doc == doc
    assert read_sig == sig
    assert read_pub_pem == pub_pem
    assert read_manifest["original_filename"] == "cdat_lectura.txt"
    assert read_manifest["document_sha256"] == calculate_sha256(doc)
    assert read_manifest["key_size_bits"] == 3072


# ==============================================================================
# 3. PRUEBAS DE VERIFICACIÓN INTEGRAL (9-10)
# ==============================================================================

def test_verify_package_valid(key_pair):
    """9. La verificación de un paquete válido debe retornar status VALID con mensaje explicativo."""
    private_key, public_key = key_pair
    doc = b"Certificado CDAT integro para verificacion completa"
    sig = sign_document(doc, private_key)
    pub_pem = serialize_public_key(public_key)
    manifest = create_manifest("cdat_verif.txt", doc, 3072)

    zip_bytes = build_zip_package(doc, sig, pub_pem, manifest)
    result = verify_package(zip_bytes)

    assert result.status == "VALID"
    assert result.signature_valid is True
    assert result.hash_match is True
    assert "Firma criptográfica válida" in result.message


def test_verify_package_modified_document(key_pair):
    """10. Si el documento dentro del paquete es alterado, debe retornar INVALID."""
    private_key, public_key = key_pair
    doc = b"Valor del ahorro: $5.000.000 COP"
    sig = sign_document(doc, private_key)
    pub_pem = serialize_public_key(public_key)
    manifest = create_manifest("cdat_ahorro.txt", doc, 3072)

    # Construir ZIP con el documento alterado manteniendo la firma original
    altered_doc = b"Valor del ahorro: $50.000.000 COP"
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w") as zf:
        zf.writestr("documento_original.bin", altered_doc)
        zf.writestr("firma.sig", sig)
        zf.writestr("clave_publica.pem", pub_pem)
        zf.writestr("manifest.json", json.dumps(manifest).encode("utf-8"))

    result = verify_package(zip_buffer.getvalue())

    assert result.status == "INVALID"
    assert result.signature_valid is False
    assert result.hash_match is False
    assert "Firma criptográfica inválida" in result.message


# ==============================================================================
# 4. PRUEBAS DE MANEJO DE CORRUPCIÓN Y CLAVES (11-13)
# ==============================================================================

def test_corrupted_signature(key_pair):
    """11. Una firma alterada o truncada debe detectarse como firma INVALID."""
    private_key, public_key = key_pair
    doc = b"Documento con firma corrupta"
    sig = sign_document(doc, private_key)
    pub_pem = serialize_public_key(public_key)
    manifest = create_manifest("demo_corrupt_sig.txt", doc, 3072)

    # Corromper bytes de la firma
    corrupted_sig = bytearray(sig)
    corrupted_sig[10] ^= 0xFF
    corrupted_sig = bytes(corrupted_sig)

    # Probar verificación con archivo individual
    indiv_result = verify_individual_files(doc, corrupted_sig, pub_pem, "demo.txt")
    assert indiv_result.status == "INVALID"
    assert indiv_result.signature_valid is False

    # Probar dentro de un paquete ZIP
    zip_bytes = build_zip_package(doc, corrupted_sig, pub_pem, manifest)
    pkg_result = verify_package(zip_bytes)
    assert pkg_result.status == "INVALID"
    assert pkg_result.signature_valid is False


def test_invalid_public_key(key_pair):
    """12. Una clave pública inválida, corrupta o que no sea PEM RSA debe arrojar ERROR."""
    private_key, _ = key_pair
    doc = b"Documento con clave publica corrupta"
    sig = sign_document(doc, private_key)
    invalid_pub_pem = b"-----BEGIN PUBLIC KEY-----\nNOT_A_VALID_KEY\n-----END PUBLIC KEY-----"

    # Verificación en archivos individuales
    result_indiv = verify_individual_files(doc, sig, invalid_pub_pem, "demo.txt")
    assert result_indiv.status == "ERROR"
    assert "no es válida" in result_indiv.message

    # En paquete ZIP
    manifest = create_manifest("demo.txt", doc, 3072)
    zip_bytes = build_zip_package(doc, sig, invalid_pub_pem, manifest)
    result_pkg = verify_package(zip_bytes)
    assert result_pkg.status == "ERROR"
    assert "no es válida" in result_pkg.message


def test_corrupted_manifest(key_pair):
    """13. Un manifiesto con JSON corrupto o campos faltantes debe generar estado ERROR."""
    private_key, public_key = key_pair
    doc = b"Documento con manifiesto corrupto"
    sig = sign_document(doc, private_key)
    pub_pem = serialize_public_key(public_key)

    # 13.a Manifiesto con sintaxis JSON rota
    bad_json_zip = io.BytesIO()
    with zipfile.ZipFile(bad_json_zip, mode="w") as zf:
        zf.writestr("documento_original.bin", doc)
        zf.writestr("firma.sig", sig)
        zf.writestr("clave_publica.pem", pub_pem)
        zf.writestr("manifest.json", b"{json_invalido: true,,}")

    result_bad_json = verify_package(bad_json_zip.getvalue())
    assert result_bad_json.status == "ERROR"
    assert "manifest.json" in result_bad_json.message

    # 13.b Manifiesto con campos obligatorios faltantes
    incomplete_manifest = {"version": "1.0", "original_filename": "demo.txt"}
    missing_fields_zip = io.BytesIO()
    with zipfile.ZipFile(missing_fields_zip, mode="w") as zf:
        zf.writestr("documento_original.bin", doc)
        zf.writestr("firma.sig", sig)
        zf.writestr("clave_publica.pem", pub_pem)
        zf.writestr("manifest.json", json.dumps(incomplete_manifest).encode("utf-8"))

    result_missing = verify_package(missing_fields_zip.getvalue())
    assert result_missing.status == "ERROR"
    assert "campos obligatorios" in result_missing.message


# ==============================================================================
# 5. PRUEBAS DE SEGURIDAD ZIP Y LÍMITES DE ENTRADA (14-16)
# ==============================================================================

def test_invalid_zip_file():
    """14. Un archivo que no sea un ZIP válido debe retornar estado ERROR."""
    corrupted_data = b"ESTO NO ES UN ARCHIVO ZIP VALIDO EN LO ABSOLUTO"

    result = verify_package(corrupted_data)

    assert result.status == "ERROR"
    assert "no es un paquete ZIP válido" in result.message


def test_zip_duplicate_or_unexpected_entries(key_pair):
    """15. Un paquete ZIP con entradas duplicadas, archivos no autorizados o Zip Slip debe rechazarse."""
    private_key, public_key = key_pair
    doc = b"Documento de prueba de seguridad ZIP"
    sig = sign_document(doc, private_key)
    pub_pem = serialize_public_key(public_key)
    manifest = json.dumps(create_manifest("demo.txt", doc, 3072)).encode("utf-8")

    # 15.a Intento de Zip Slip (ruta relativa con ..)
    slip_zip = io.BytesIO()
    with zipfile.ZipFile(slip_zip, mode="w") as zf:
        zf.writestr("../documento_original.bin", doc)
        zf.writestr("firma.sig", sig)
        zf.writestr("clave_publica.pem", pub_pem)
        zf.writestr("manifest.json", manifest)

    res_slip = verify_package(slip_zip.getvalue())
    assert res_slip.status == "ERROR"
    assert "rutas relativas" in res_slip.message or "no permitidos" in res_slip.message

    # 15.b Archivo no autorizado dentro del paquete
    extra_zip = io.BytesIO()
    with zipfile.ZipFile(extra_zip, mode="w") as zf:
        zf.writestr("documento_original.bin", doc)
        zf.writestr("firma.sig", sig)
        zf.writestr("clave_publica.pem", pub_pem)
        zf.writestr("manifest.json", manifest)
        zf.writestr("script_malicioso.sh", b"echo hacked")

    res_extra = verify_package(extra_zip.getvalue())
    assert res_extra.status == "ERROR"
    assert "no autorizado" in res_extra.message

    # 15.c Entradas duplicadas
    dup_zip = io.BytesIO()
    with zipfile.ZipFile(dup_zip, mode="w") as zf:
        zf.writestr("documento_original.bin", doc)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            zf.writestr("documento_original.bin", b"otro contenido")
        zf.writestr("firma.sig", sig)
        zf.writestr("clave_publica.pem", pub_pem)
        zf.writestr("manifest.json", manifest)

    res_dup = verify_package(dup_zip.getvalue())
    assert res_dup.status == "ERROR"
    assert "duplicadas" in res_dup.message


def test_document_size_validation():
    """16. Debe rechazarse adecuadamente tanto documentos vacíos como aquellos que superen 20 MB."""
    # Validación de documento vacío
    with pytest.raises(ValueError, match="vacío"):
        validate_document_size(b"")

    # Validación de documento que excede 20 MB
    large_doc = b"A" * (MAX_DOCUMENT_SIZE + 1024)
    with pytest.raises(ValueError, match="excede el tamaño máximo"):
        validate_document_size(large_doc)

    # Documento de tamaño válido (ej. 1 KB)
    valid_doc = b"A" * 1024
    validate_document_size(valid_doc)  # No debe lanzar excepción


# ==============================================================================
# PRUEBAS ADICIONALES: ARCHIVOS INDIVIDUALES Y SANITIZACIÓN
# ==============================================================================

def test_verify_individual_files_valid(key_pair):
    """Verificación exitosa cargando archivos por separado."""
    private_key, public_key = key_pair
    doc = b"Contenido individual para comprobacion"
    sig = sign_document(doc, private_key)
    pub_pem = serialize_public_key(public_key)

    result = verify_individual_files(doc, sig, pub_pem, "certificado.pdf")
    assert result.status == "VALID"
    assert result.signature_valid is True
    assert "Firma criptográfica válida" in result.message


def test_verify_individual_files_tampered(key_pair):
    """Verificación fallida en archivos individuales si se altera el documento."""
    private_key, public_key = key_pair
    doc = b"Contenido individual original"
    sig = sign_document(doc, private_key)
    pub_pem = serialize_public_key(public_key)

    tampered_doc = b"Contenido individual MODIFICADO"
    result = verify_individual_files(tampered_doc, sig, pub_pem, "certificado.pdf")
    assert result.status == "INVALID"
    assert result.signature_valid is False


def test_filename_sanitization():
    """Comprobar sanitización de nombres de archivo potencialmente peligrosos."""
    assert sanitize_filename("..\\..\\secreto.txt") == "secreto.txt"
    assert sanitize_filename("../../../etc/passwd") == "passwd"
    assert sanitize_filename("archivo con espacios (1).pdf") == "archivo con espacios (1).pdf"
    assert sanitize_filename("") == "documento_original.bin"
