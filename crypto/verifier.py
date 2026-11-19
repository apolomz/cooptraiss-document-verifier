
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def verify_signature(
    document: bytes,
    signature: bytes,
    public_key: rsa.RSAPublicKey
) -> bool:
    """
    Verifica una firma RSA-PSS utilizando SHA-256.

    Returns:
        True si la firma es válida.
        False si la firma no corresponde al documento.
    """
    try:
        public_key.verify(
            signature,
            document,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except InvalidSignature:
        return False
