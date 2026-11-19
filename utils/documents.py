"""
Módulo de utilidades documentales y gestión segura de paquetes ZIP.

Proporciona funciones para:
- Sanitización y validación de documentos y nombres de archivos.
- Generación de manifiestos estructurados en JSON.
- Empaquetado seguro en memoria (ZIP) sin persistencia en disco.
- Lectura, inspección y validación estricta de paquetes ZIP (prevención de Zip Slip,
  Zip Bomb, entradas duplicadas y archivos inesperados).
- Verificación integral de paquetes y archivos individuales.
"""

from __future__ import annotations

import io
import json
import os
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from crypto.keys import load_public_key
from crypto.signer import calculate_sha256
from crypto.verifier import verify_signature

# Límites de seguridad operativa
MAX_DOCUMENT_SIZE = 20 * 1024 * 1024  # 20 MB por documento
MAX_UNCOMPRESSED_ZIP_SIZE = 50 * 1024 * 1024  # 50 MB tamaño total descomprimido

REQUIRED_ZIP_FILES = (
    "documento_original.bin",
    "firma.sig",
    "clave_publica.pem",
    "manifest.json",
)

ALLOWED_ZIP_FILES = set(REQUIRED_ZIP_FILES)

REQUIRED_MANIFEST_FIELDS = {
    "version",
    "original_filename",
    "hash_algorithm",
    "signature_algorithm",
    "key_size_bits",
    "document_sha256",
}


class PackageValidationError(ValueError):
    """Excepción lanzada cuando un paquete o documento no cumple las validaciones de seguridad."""
    pass


@dataclass
class VerificationResult:
    """Resultado estructurado de la verificación documental."""
    status: str  # "VALID", "INVALID", "ERROR"
    message: str
    document_sha256: str = ""
    manifest_sha256: str = ""
    hash_match: bool = False
    signature_valid: bool = False
    original_filename: str = ""
    key_size_bits: int = 3072
    algorithm_info: str = "RSA-PSS con SHA-256"
    details: dict[str, Any] = field(default_factory=dict)


def sanitize_filename(filename: str) -> str:
    """
    Sanitiza el nombre de un archivo para evitar rutas relativas,
    caracteres de control o intentos de path traversal.
    """
    if not filename:
        return "documento_original.bin"

    # Extraer el nombre base eliminando posibles rutas Unix o Windows
    base_name = os.path.basename(filename.replace("\\", "/"))
    # Permitir solo caracteres seguros: alfanuméricos, espacios, guiones, puntos, paréntesis y guiones bajos
    clean_name = re.sub(r"[^\w\s\.\(\)\-_]", "_", base_name).strip()
    # Eliminar dobles puntos consecutivos que puedan indicar retroceso de directorio
    clean_name = re.sub(r"\.{2,}", ".", clean_name)

    return clean_name if clean_name else "documento_original.bin"


def validate_document_size(document_bytes: bytes) -> None:
    """
    Verifica que el documento no esté vacío y no exceda el límite de 20 MB.
    """
    if not document_bytes or len(document_bytes) == 0:
        raise ValueError("El documento no contiene datos o está vacío (0 bytes).")

    if len(document_bytes) > MAX_DOCUMENT_SIZE:
        raise ValueError(
            f"El documento excede el tamaño máximo permitido de 20 MB "
            f"(tamaño actual: {len(document_bytes) / (1024 * 1024):.2f} MB)."
        )


def create_manifest(
    original_filename: str,
    document_bytes: bytes,
    key_size_bits: int = 3072,
) -> dict[str, Any]:
    """
    Crea el diccionario con los metadatos descriptivos del manifiesto.
    """
    validate_document_size(document_bytes)

    sha256_hash = calculate_sha256(document_bytes)
    clean_filename = sanitize_filename(original_filename)

    return {
        "version": "1.0",
        "original_filename": clean_filename,
        "file_size_bytes": len(document_bytes),
        "hash_algorithm": "SHA-256",
        "signature_algorithm": "RSA-PSS con SHA-256",
        "key_size_bits": key_size_bits,
        "document_sha256": sha256_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "application": "COOPTRAISS | Verificador documental",
        "academic_context": (
            "Auditoría de seguridad de la información - "
            "Proceso de Ahorro COOPTRAISS (Universidad del Valle)"
        ),
        "academic_disclaimer": (
            "Prototipo académico independiente. Sin validez legal o contractual. "
            "No constituye un canal oficial de COOPTRAISS."
        ),
    }


def build_zip_package(
    document_bytes: bytes,
    signature_bytes: bytes,
    public_key_pem: bytes,
    manifest: dict[str, Any],
) -> bytes:
    """
    Construye un paquete ZIP en memoria con los cuatro componentes requeridos:
    - documento_original.bin
    - firma.sig
    - clave_publica.pem
    - manifest.json

    Returns:
        bytes con el contenido binario del archivo ZIP.
    """
    validate_document_size(document_bytes)

    if not signature_bytes:
        raise ValueError("La firma criptográfica no puede estar vacía.")

    if not public_key_pem:
        raise ValueError("La clave pública PEM no puede estar vacía.")

    manifest_json = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")

    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("documento_original.bin", document_bytes)
        zip_file.writestr("firma.sig", signature_bytes)
        zip_file.writestr("clave_publica.pem", public_key_pem)
        zip_file.writestr("manifest.json", manifest_json)

    return zip_buffer.getvalue()


def read_and_validate_zip_package(
    zip_bytes: bytes,
) -> tuple[bytes, bytes, bytes, dict[str, Any]]:
    """
    Lee y valida estrictamente un paquete ZIP en memoria.

    Comprueba:
    1. Que sea un archivo ZIP válido.
    2. Que no tenga entradas duplicadas.
    3. Que no contenga rutas relativas o intentos de Zip Slip.
    4. Que no exceda los límites de tamaño descomprimido (Zip Bomb).
    5. Que contenga exactamente los archivos requeridos.
    6. Que el manifiesto tenga un formato JSON válido y los campos obligatorios.

    Returns:
        Tupla con (document_bytes, signature_bytes, public_key_pem, manifest_dict)
    """
    if not zip_bytes or len(zip_bytes) == 0:
        raise PackageValidationError("El paquete ZIP está vacío o no contiene datos.")

    try:
        zip_stream = io.BytesIO(zip_bytes)
        with zipfile.ZipFile(zip_stream, mode="r") as zip_file:
            infolist = zip_file.infolist()

            if not infolist:
                raise PackageValidationError("El archivo ZIP no contiene ningún archivo.")

            names = [info.filename for info in infolist]

            # 1. Comprobación de entradas duplicadas
            if len(names) != len(set(names)):
                raise PackageValidationError(
                    "El paquete ZIP contiene entradas de archivo duplicadas."
                )

            # 2. Comprobación de rutas y nombres permitidos (Zip Slip y archivos extraños)
            for name in names:
                if "/" in name or "\\" in name or ".." in name:
                    raise PackageValidationError(
                        f"El paquete ZIP contiene rutas relativas o directorios no permitidos: '{name}'."
                    )
                if name not in ALLOWED_ZIP_FILES:
                    raise PackageValidationError(
                        f"El paquete ZIP contiene un archivo no reconocido o no autorizado: '{name}'."
                    )

            # 3. Comprobación de archivos requeridos
            missing_files = ALLOWED_ZIP_FILES - set(names)
            if missing_files:
                raise PackageValidationError(
                    f"El paquete ZIP está incompleto. Faltan los siguientes archivos: {', '.join(sorted(missing_files))}."
                )

            # 4. Comprobación de límites de descompresión (Zip Bomb)
            total_uncompressed_size = 0
            for info in infolist:
                if info.file_size > MAX_DOCUMENT_SIZE:
                    raise PackageValidationError(
                        f"El archivo '{info.filename}' excede el tamaño máximo permitido de 20 MB."
                    )
                total_uncompressed_size += info.file_size

            if total_uncompressed_size > MAX_UNCOMPRESSED_ZIP_SIZE:
                raise PackageValidationError(
                    f"El tamaño total descomprimido ({total_uncompressed_size / (1024 * 1024):.2f} MB) "
                    f"supera el límite de seguridad de 50 MB."
                )

            # 5. Extracción segura en memoria
            document_bytes = zip_file.read("documento_original.bin")
            signature_bytes = zip_file.read("firma.sig")
            public_key_pem = zip_file.read("clave_publica.pem")
            manifest_raw = zip_file.read("manifest.json")

    except zipfile.BadZipFile as error:
        raise PackageValidationError("El archivo proporcionado no es un paquete ZIP válido o está dañado.") from error

    # Validar contenidos extraídos
    if len(document_bytes) == 0:
        raise PackageValidationError("El documento original dentro del paquete está vacío (0 bytes).")

    if len(signature_bytes) == 0:
        raise PackageValidationError("El archivo de firma 'firma.sig' dentro del paquete está vacío.")

    if len(public_key_pem) == 0:
        raise PackageValidationError("La clave pública 'clave_publica.pem' dentro del paquete está vacía.")

    # Validar formato y campos del manifiesto
    try:
        manifest_dict = json.loads(manifest_raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise PackageValidationError("El archivo 'manifest.json' está dañado o no es un JSON válido.") from error

    if not isinstance(manifest_dict, dict):
        raise PackageValidationError("El contenido de 'manifest.json' no es un objeto JSON válido.")

    missing_manifest_fields = REQUIRED_MANIFEST_FIELDS - set(manifest_dict.keys())
    if missing_manifest_fields:
        raise PackageValidationError(
            f"El manifiesto carece de los campos obligatorios: {', '.join(sorted(missing_manifest_fields))}."
        )

    return document_bytes, signature_bytes, public_key_pem, manifest_dict


def verify_package(zip_bytes: bytes) -> VerificationResult:
    """
    Verifica un paquete ZIP completo en memoria.

    Distingue claramente entre:
    - VALID: Documento intacto, coincidencia con el manifiesto y firma matemáticamente válida.
    - INVALID: Documento modificado, firma alterada o discrepancia criptográfica.
    - ERROR: Fallo de formato, archivo ZIP corrupto, clave no RSA o manifiesto inválido.
    """
    try:
        doc_bytes, sig_bytes, pub_pem, manifest = read_and_validate_zip_package(zip_bytes)
    except (PackageValidationError, ValueError) as error:
        return VerificationResult(
            status="ERROR",
            message=f"Error en la estructura del paquete: {error}",
            details={"error_type": "PackageValidationError", "description": str(error)},
        )
    except Exception as error:  # pylint: disable=broad-except
        return VerificationResult(
            status="ERROR",
            message=f"Error inesperado al procesar el paquete: {error}",
            details={"error_type": type(error).__name__, "description": str(error)},
        )

    # 1. Calcular hash SHA-256 del documento extraído
    calculated_hash = calculate_sha256(doc_bytes)
    manifest_hash = str(manifest.get("document_sha256", "")).strip().lower()
    hash_match = (calculated_hash.lower() == manifest_hash)
    original_filename = str(manifest.get("original_filename", "documento_original.bin"))
    key_size_bits = int(manifest.get("key_size_bits", 3072))

    # 2. Cargar la clave pública
    try:
        public_key = load_public_key(pub_pem)
    except ValueError as error:
        return VerificationResult(
            status="ERROR",
            message=f"La clave pública contenida en el paquete no es válida: {error}",
            document_sha256=calculated_hash,
            manifest_sha256=manifest_hash,
            hash_match=hash_match,
            original_filename=original_filename,
            key_size_bits=key_size_bits,
            details={"error_type": "InvalidPublicKey", "description": str(error)},
        )

    # 3. Verificar la firma criptográfica RSA-PSS
    signature_valid = verify_signature(doc_bytes, sig_bytes, public_key)

    details = {
        "manifest": manifest,
        "document_size_bytes": len(doc_bytes),
        "signature_size_bytes": len(sig_bytes),
        "hash_match": hash_match,
        "signature_valid": signature_valid,
    }

    # 4. Determinar resultado final
    if hash_match and signature_valid:
        return VerificationResult(
            status="VALID",
            message=(
                "Firma criptográfica válida. El documento corresponde a la firma "
                "proporcionada y no se detectaron alteraciones respecto al contenido firmado."
            ),
            document_sha256=calculated_hash,
            manifest_sha256=manifest_hash,
            hash_match=True,
            signature_valid=True,
            original_filename=original_filename,
            key_size_bits=key_size_bits,
            details=details,
        )

    # Si el hash no coincide con el manifiesto o la firma es inválida
    reasons = []
    if not hash_match:
        reasons.append(
            "El hash SHA-256 del documento no coincide con el registrado en el manifiesto."
        )
    if not signature_valid:
        reasons.append(
            "La firma criptográfica RSA-PSS no corresponde al contenido del documento o a la clave pública."
        )

    return VerificationResult(
        status="INVALID",
        message="Firma criptográfica inválida. " + " ".join(reasons),
        document_sha256=calculated_hash,
        manifest_sha256=manifest_hash,
        hash_match=hash_match,
        signature_valid=signature_valid,
        original_filename=original_filename,
        key_size_bits=key_size_bits,
        details=details,
    )


def verify_individual_files(
    document_bytes: bytes,
    signature_bytes: bytes,
    public_key_pem: bytes,
    original_filename: str = "",
) -> VerificationResult:
    """
    Verifica un documento a partir de sus tres archivos individuales:
    - documento
    - firma (.sig)
    - clave pública (.pem)
    """
    clean_filename = sanitize_filename(original_filename) if original_filename else "documento_original"

    # Validar entradas obligatorias
    try:
        validate_document_size(document_bytes)
    except ValueError as error:
        return VerificationResult(
            status="ERROR",
            message=f"Error en el documento proporcionado: {error}",
            original_filename=clean_filename,
        )

    if not signature_bytes or len(signature_bytes) == 0:
        return VerificationResult(
            status="ERROR",
            message="El archivo de firma (.sig) está vacío o no fue suministrado.",
            original_filename=clean_filename,
        )

    if not public_key_pem or len(public_key_pem) == 0:
        return VerificationResult(
            status="ERROR",
            message="El archivo de clave pública (.pem) está vacío o no fue suministrado.",
            original_filename=clean_filename,
        )

    calculated_hash = calculate_sha256(document_bytes)

    # Cargar y validar la clave pública
    try:
        public_key = load_public_key(public_key_pem)
        key_size_bits = public_key.key_size
    except ValueError as error:
        return VerificationResult(
            status="ERROR",
            message=f"La clave pública PEM no es válida: {error}",
            document_sha256=calculated_hash,
            original_filename=clean_filename,
            details={"error_type": "InvalidPublicKey", "description": str(error)},
        )

    # Verificar la firma criptográfica
    signature_valid = verify_signature(document_bytes, signature_bytes, public_key)

    details = {
        "document_size_bytes": len(document_bytes),
        "signature_size_bytes": len(signature_bytes),
        "signature_valid": signature_valid,
        "key_size_bits": key_size_bits,
    }

    if signature_valid:
        return VerificationResult(
            status="VALID",
            message=(
                "Firma criptográfica válida. El documento corresponde a la firma "
                "proporcionada y no se detectaron alteraciones respecto al contenido firmado."
            ),
            document_sha256=calculated_hash,
            manifest_sha256=calculated_hash,
            hash_match=True,
            signature_valid=True,
            original_filename=clean_filename,
            key_size_bits=key_size_bits,
            details=details,
        )

    return VerificationResult(
        status="INVALID",
        message=(
            "Firma criptográfica inválida. La firma no corresponde al documento proporcionado "
            "o se utilizó una clave pública diferente."
        ),
        document_sha256=calculated_hash,
        manifest_sha256="",
        hash_match=False,
        signature_valid=False,
        original_filename=clean_filename,
        key_size_bits=key_size_bits,
        details=details,
    )
