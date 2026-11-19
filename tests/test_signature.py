
import pytest

from crypto.keys import generate_key_pair, serialize_public_key, load_public_key
from crypto.signer import calculate_sha256, sign_document
from crypto.verifier import verify_signature


@pytest.fixture(scope="module")
def key_pair():
    """Genera un par de claves para las pruebas del módulo."""
    return generate_key_pair()


def test_valid_signature(key_pair):
    """Una firma debe verificarse correctamente."""
    private_key, public_key = key_pair
    document = b"Certificado CDAT de prueba - COOPTRAISS"

    signature = sign_document(document, private_key)

    assert verify_signature(document, signature, public_key) is True


def test_modified_document_fails(key_pair):
    """Una modificación del documento debe invalidar la firma."""
    private_key, public_key = key_pair
    original_document = b"Certificado CDAT de prueba - COOPTRAISS"

    signature = sign_document(original_document, private_key)

    modified_document = b"Certificado CDAT ALTERADO - COOPTRAISS"

    assert verify_signature(modified_document, signature, public_key) is False


def test_wrong_public_key_fails(key_pair):
    """Una clave pública diferente no debe validar la firma."""
    private_key, _ = key_pair
    _, wrong_public_key = generate_key_pair()

    document = b"Documento de prueba"

    signature = sign_document(document, private_key)

    assert verify_signature(document, signature, wrong_public_key) is False


def test_public_key_serialization(key_pair):
    """La clave pública debe poder exportarse e importarse."""
    _, public_key = key_pair

    public_key_pem = serialize_public_key(public_key)
    loaded_public_key = load_public_key(public_key_pem)

    assert isinstance(loaded_public_key, type(public_key))


def test_sha256_length():
    """SHA-256 debe producir un hash hexadecimal de 64 caracteres."""
    document = b"Documento de prueba"

    digest = calculate_sha256(document)

    assert len(digest) == 64


def test_empty_document_fails(key_pair):
    """No debe permitirse firmar documentos vacíos."""
    private_key, _ = key_pair

    with pytest.raises(ValueError):
        sign_document(b"", private_key)
