
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def calculate_sha256(document: bytes) -> str:
    """
    Calcula el hash SHA-256 de un documento.
    """
    return hashlib.sha256(document).hexdigest()


def sign_document(
    document: bytes,
    private_key: rsa.RSAPrivateKey
) -> bytes:
    """
    Genera una firma digital criptográfica usando RSA-PSS y SHA-256.
    """
    if not document:
        raise ValueError("No se puede firmar un documento vacío.")

    signature = private_key.sign(
        document,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature
