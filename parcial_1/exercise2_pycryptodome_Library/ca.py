from alice import hash_pdf_content, sign_hash
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def extract_signature_from_content(content, signature_id):
    signature_id_bytes = signature_id if isinstance(signature_id, bytes) else signature_id.encode()
    signature_pos = content.rfind(signature_id_bytes)
    if signature_pos != -1:
        signature_start = signature_pos + len(signature_id_bytes)
        signature = content[signature_start:]
        content_without_signature = content[:signature_pos]
        print(f"{signature_id} extracted: {signature[:10]}... length: {len(signature)}")
        return content_without_signature, signature
    else:
        print(f"{signature_id} not found.")
        return content, None

def verify_signature(hash_obj, signature, public_key):
    if signature is None:
        print("Signature is None, cannot verify.")
        return False
    try:
        verifier = pkcs1_15.new(RSA.import_key(public_key))
        verifier.verify(hash_obj, signature)
        print("The signature is valid.")
        return True
    except (ValueError, TypeError) as e:
        print(f"The signature is not valid. Error: {str(e)}")
        return False

def ca_verifies_and_signs_document(content, ca_private_key, alice_public_key):
    print("CA starts verifying document...")
    content_without_signature, alice_signature = extract_signature_from_content(content, b"--ALICESIGNATURE--")
    hash_obj = hash_pdf_content(content_without_signature)
    if verify_signature(hash_obj, alice_signature, alice_public_key):
        ca_signature = sign_hash(hash_obj, ca_private_key)
        signed_content = content_without_signature + b"--CASIGNATURE--" + ca_signature
        print("CA's signature process completed.")
        return signed_content
    else:
        print("CA could not verify Alice's signature.")
        return content
