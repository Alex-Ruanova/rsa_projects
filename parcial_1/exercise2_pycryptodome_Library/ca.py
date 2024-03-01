from alice import hash_pdf_content, sign_hash, append_signature_to_pdf
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

def extract_signature_from_pdf(pdf_path, signature_id):
    with open(pdf_path, 'rb') as pdf_file:
        pdf_content = pdf_file.read()
    signature_pos = pdf_content.rfind(signature_id.encode())  # Find the unique identifier
    if signature_pos != -1:
        signature_start = signature_pos + len(signature_id)  # Adjust to start of signature
        signature_end = pdf_content.find(b'--', signature_start)  # Assume signature is followed by another delimiter
        signature = pdf_content[signature_start:signature_end] if signature_end != -1 else pdf_content[signature_start:]
        print(f"{signature_id} extracted: {signature[:10]}... length: {len(signature)}")
        return signature
    else:
        print(f"{signature_id} not found in PDF file.")
        return None

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

def ca_verifies_and_signs_document(input_pdf_path, ca_private_key_path, alice_public_key_path, output_pdf_path):
    print("CA starts verifying document...")
    hash_obj = hash_pdf_content(input_pdf_path, exclude_signature=True)
    alice_signature = extract_signature_from_pdf(input_pdf_path, "--ALICESIGNATURE--")
    if alice_signature is None:
        print("Failed to extract Alice's signature from the document. Aborting verification.")
        return
    with open(alice_public_key_path, 'r') as f:
        alice_public_key = f.read()
    is_signature_valid = verify_signature(hash_obj, alice_signature, alice_public_key)
    if is_signature_valid:
        with open(ca_private_key_path, 'r') as f:
            ca_private_key = f.read()
        ca_signature = sign_hash(hash_obj, ca_private_key)
        append_signature_to_pdf(input_pdf_path, ca_signature, output_pdf_path, "--CASIGNATURE--")
        print("CA's signature process completed.")
    else:
        print("CA could not verify Alice's signature.")