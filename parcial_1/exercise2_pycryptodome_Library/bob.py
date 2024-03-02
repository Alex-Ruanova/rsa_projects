from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def hash_content(content):
    hasher = SHA256.new(content)
    print(f"Hash calculado para la verificación: {hasher.hexdigest()}")
    return hasher


def extract_signature_from_content(content, signature_id):
    print(f"Intentando extraer firma con ID: {signature_id.decode()}")
    signature_pos = content.rfind(signature_id)
    if signature_pos != -1:
        signature_start = signature_pos + len(signature_id)
        content_end = content.find(b"--", signature_start)  # Busca el siguiente delimitador
        if content_end == -1:  # Ajuste aquí para manejar el final de la firma correctamente
            content_end = len(content)
        signature = content[signature_start:content_end]
        content_without_signature = content[:signature_pos]
        print(f"Firma {signature_id.decode()} extraída con éxito.")
        print(f"Longitud de la firma: {len(signature)}")
        return content_without_signature, signature
    else:
        print(f"Firma {signature_id.decode()} no encontrada.")
        return content, None


def verify_signature(hash_obj, signature, public_key):
    if signature is None:
        print("La firma es None, no se puede verificar.")
        return False
    try:
        public_key_obj = RSA.import_key(public_key)
        verifier = pkcs1_15.new(public_key_obj)
        verifier.verify(hash_obj, signature)
        print("La firma es válida.")
        return True
    except (ValueError, TypeError) as e:
        print(f"La firma no es válida. Error: {e}")
        # Esta línea ya no se ejecutará si signature es None, por lo que se puede quitar o comentar
        # print(f"Longitud de la firma para verificación: {len(signature)}")
        return False


def bob_verifies_document(signed_content, alice_public_key_str, ca_public_key_str):
    print("Bob comienza a verificar el documento...")
    # Extraer y verificar la firma de Alice
    content_without_alice_sig, alice_signature = extract_signature_from_content(signed_content, b"--ALICESIGNATURE--")
    hash_obj_alice = hash_content(content_without_alice_sig)  # Corrección aquí: elimina el segundo argumento
    if not verify_signature(hash_obj_alice, alice_signature, alice_public_key_str):
        print("La verificación de la firma de Alice falló.")
        return False

    # Extraer y verificar la firma de la CA
    content_without_ca_sig, ca_signature = extract_signature_from_content(content_without_alice_sig, b"--CASIGNATURE--")
    hash_obj_ca = hash_content(content_without_ca_sig)  # Asegúrate de que esta llamada también sea correcta
    if not verify_signature(hash_obj_ca, ca_signature, ca_public_key_str):
        print("La verificación de la firma de la CA falló.")
        return False

    print("Bob verificó ambas firmas con éxito.")
    return True

