from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from alice import hash_pdf_content
from ca import extract_signature_from_content

def verify_signature(hash_obj, signature, public_key):
    try:
        # Asegúrate de que public_key sea un objeto RsaKey
        if isinstance(public_key, (bytes, str)):
            public_key = RSA.import_key(public_key)

        verifier = pkcs1_15.new(public_key)
        verifier.verify(hash_obj, signature)
        print("The signature is valid.")
        return True
    except (ValueError, TypeError) as e:
        print(f"The signature is not valid. Error: {str(e)}")
        return False

def verify_signature(hash_obj, signature, public_key):
    try:
        # Convierte la clave pública a un objeto RsaKey si aún no lo es
        if isinstance(public_key, (bytes, str)):
            public_key = RSA.import_key(public_key)  # Importa la clave pública

        verifier = pkcs1_15.new(public_key)
        verifier.verify(hash_obj, signature)
        print("The signature is valid.")
        return True
    except (ValueError, TypeError) as e:
        print(f"The signature is not valid. Error: {str(e)}")
        return False

def bob_verifies_document(content, alice_public_key, ca_public_key):
    print("Bob starts verifying document...")
    content_without_alice_signature, alice_signature = extract_signature_from_content(content, b"--ALICESIGNATURE--")
    hash_obj_alice = hash_pdf_content(content_without_alice_signature, exclude_signature=True)
    alice_verified = verify_signature(hash_obj_alice, alice_signature, alice_public_key)

    content_without_ca_signature, ca_signature = extract_signature_from_content(content_without_alice_signature, b"--CASIGNATURE--")
    hash_obj_ca = hash_pdf_content(content_without_ca_signature, exclude_signature=True)
    ca_verified = verify_signature(hash_obj_ca, ca_signature, ca_public_key)

    if alice_verified and ca_verified:
        print("Bob verified both signatures successfully.")
    else:
        print("Verification failed.")
