from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def hash_content(content):
    hasher = SHA256.new(content)
    print(f"Hash calculado para la verificación: {hasher.hexdigest()}")
    return hasher


def extract_signature_from_content(content, signature_id):
    print(f"Attempting to extract signature with ID: {signature_id.decode()}")
    signature_pos = content.rfind(signature_id)
    if signature_pos != -1:
        signature_start = signature_pos + len(signature_id)
        content_end = content.find(b"--", signature_start)  # Look for the next delimiter
        if content_end == -1:  # Adjust here to handle the end of the signature correctly
            content_end = len(content)
        signature = content[signature_start:content_end]
        content_without_signature = content[:signature_pos]
        print(f"Signature {signature_id.decode()} extracted successfully.")
        print(f"Signature length: {len(signature)}")
        return content_without_signature, signature
    else:
        print(f"Signature {signature_id.decode()} extracted successfully.")
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
    content_without_alice_signature, alice_signature = extract_signature_from_content(signed_content,
                                                                                      b"--ALICESIGNATURE--")
    hash_obj_alice = hash_content(content_without_alice_signature)
    print(f"Hash for verifying Alice's signature: {hash_obj_alice.hexdigest()}")
    # Proceed with Alice's signature verification...

    content_without_ca_signature, ca_signature = extract_signature_from_content(content_without_alice_signature,
                                                                                b"--CASIGNATURE--")
    hash_obj_ca = hash_content(content_without_ca_signature)
    print(f"Hash for verifying CA's signature: {hash_obj_ca.hexdigest()}")
    # Proceed with CA's signature verification...


