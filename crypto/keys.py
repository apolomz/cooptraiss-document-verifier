
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_key_pair(
    key_size: int = 3072
) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Genera un par de claves RSA.

    Returns:
        Tupla con la clave privada y la clave pública.
    """
    if key_size < 2048:
        raise ValueError("El tamaño de la clave RSA debe ser de al menos 2048 bits.")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    public_key = private_key.public_key()

    return private_key, public_key


def serialize_public_key(
    public_key: rsa.RSAPublicKey
) -> bytes:
    """
    Convierte la clave pública a formato PEM.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key(
    public_key_pem: bytes
) -> rsa.RSAPublicKey:
    """
    Carga una clave pública desde un archivo o contenido PEM.
    """
    try:
        loaded_key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError) as error:
        raise ValueError("El archivo no contiene una clave pública PEM válida.") from error

    if not isinstance(loaded_key, rsa.RSAPublicKey):
        raise ValueError("La clave proporcionada no es una clave RSA.")

    return loaded_key
