from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def hash_content(content, exclude_signature=False):
    hasher = SHA256.new(content)
    print(f"Hash calculado para la verificación: {hasher.hexdigest()}")
    return hasher

def extract_signature_from_content(content, signature_id):
    print(f"Intentando extraer firma con ID: {signature_id.decode()}")
    signature_pos = content.rfind(signature_id)
    if signature_pos != -1:
        signature_start = signature_pos + len(signature_id)
        signature = content[signature_start:]
        content_without_signature = content[:signature_pos]
        print(f"Firma {signature_id.decode()} extraída con éxito.")
        print(f"Longitud de la firma: {len(signature)}")
        # Agregar log del hash del contenido sin la firma para comparar
        hash_obj = SHA256.new(content_without_signature)
        print(f"Hash del contenido sin firma: {hash_obj.hexdigest()}")
        return content_without_signature, signature
    else:
        print(f"Firma {signature_id.decode()} no encontrada.")
        return content, None


def verify_signature(hash_obj, signature, public_key):
    try:
        public_key_obj = RSA.import_key(public_key) if not isinstance(public_key, RSA.RsaKey) else public_key
        verifier = pkcs1_15.new(public_key_obj)
        verifier.verify(hash_obj, signature)
        print("La firma es válida.")
        return True
    except (ValueError, TypeError) as e:
        print(f"La firma no es válida. Error: {e}")
        # Logs adicionales para depuración
        print(f"Longitud de la firma para verificación: {len(signature)}")
        print(f"Clave pública usada para la verificación: {public_key_obj.export_key().decode()[:60]}...")
        return False


def bob_verifies_document(signed_content, alice_public_key, ca_public_key):
    print("Bob comienza a verificar el documento...")

    # Extraer y verificar la firma de Alice
    content_without_alice_sig, alice_signature = extract_signature_from_content(signed_content, b"--ALICESIGNATURE--")
    hash_obj_alice = hash_content(content_without_alice_sig)
    if not verify_signature(hash_obj_alice, alice_signature, alice_public_key):
        print("La verificación de la firma de Alice falló.")
        return False

    # Extraer y verificar la firma de la CA
    content_without_ca_sig, ca_signature = extract_signature_from_content(content_without_alice_sig, b"--CASIGNATURE--")
    hash_obj_ca = hash_content(content_without_ca_sig)
    if not verify_signature(hash_obj_ca, ca_signature, ca_public_key):
        print("La verificación de la firma de la CA falló.")
        return False

    print("Bob verificó ambas firmas con éxito.")
    return True
