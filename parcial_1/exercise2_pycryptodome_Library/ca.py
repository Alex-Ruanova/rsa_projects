from alice import hash_pdf_content, sign_hash
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def extract_signature_from_content(content, signature_id):
    print(f"Attempting to extract signature with ID: {signature_id.decode()}")
    signature_pos = content.rfind(signature_id)
    if signature_pos != -1:
        signature_start = signature_pos + len(signature_id)
        # Corrected logic to handle the end of the signature
        content_end = content.find(b"--", signature_start)
        if content_end == -1:  # If no delimiter is found, assume the signature goes until the end of the document
            signature = content[signature_start:]  # Extract to the end if no further delimiter
        else:
            signature = content[signature_start:content_end]  # Extract up to the next delimiter if found
        content_without_signature = content[:signature_pos]
        print(f"Signature {signature_id.decode()} extracted successfully.")
        print(f"Signature length: {len(signature)}")
        return content_without_signature, signature
    else:
        print(f"Signature {signature_id.decode()} extracted successfully..")
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
    hash_obj_before_ca_sign = hash_pdf_content(content_without_signature, exclude_signature=True)  # Exclude signature for hash
    print(f"Document length before removing Alice's signature: {len(content)} bytes")
    print(f"Document length after removing Alice's signature: {len(content_without_signature)} bytes")
    print(f"Hash before CA signs: {hash_obj_before_ca_sign.hexdigest()}")
    if verify_signature(hash_obj_before_ca_sign, alice_signature, alice_public_key):
        ca_signature = sign_hash(hash_obj_before_ca_sign, ca_private_key)
        signed_content_by_ca = content_without_signature + b"--CASIGNATURE--" + ca_signature
        print("CA's signature process completed.")
        return signed_content_by_ca
    else:
        print("CA could not verify Alice's signature.")
        return content


