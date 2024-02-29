from alice import hash_pdf_content, sign_hash, embed_signature_in_pdf
import PyPDF2
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import ast

def extract_signature_from_pdf(pdf_path, signature_key):
    reader = PyPDF2.PdfReader(pdf_path)
    metadata = reader.metadata
    signature = metadata.get(signature_key)
    if signature:
        signature_bytes = ast.literal_eval(signature)
        print(f"Extracted Alice's signature: {signature_bytes[:10]}... length: {len(signature_bytes)}")  # Added log
        return signature_bytes
    return None

def verify_signature(hash_obj, signature, public_key):
    try:
        pkcs1_15.new(RSA.import_key(public_key)).verify(hash_obj, signature)
        print("The signature is valid.")
        return True
    except (ValueError, TypeError):
        print("The signature is not valid.")
        return False

def embed_signature_in_pdf(pdf_path, signature, output_pdf_path, signature_key):
    reader = PyPDF2.PdfReader(pdf_path)
    writer = PyPDF2.PdfWriter()
    metadata = reader.metadata
    new_metadata = {**metadata, signature_key: str(signature)}
    writer.add_metadata(new_metadata)
    with open(output_pdf_path, 'wb') as f_out:
        writer.write(f_out)
    print("CA's signature embedded into metadata.")  # Added log

def ca_verifies_and_signs_document(input_pdf_path, ca_private_key_path, alice_public_key_path, output_pdf_path):
    print("CA starts verifying document...")
    hash_obj = hash_pdf_content(input_pdf_path)
    alice_signature = extract_signature_from_pdf(input_pdf_path, '/AliceSignature')
    with open(alice_public_key_path, 'r') as f:
        alice_public_key = f.read()
    print(f"Using Alice's public key for verification: {alice_public_key[:50]}...")  # Added log
    is_signature_valid = verify_signature(hash_obj, alice_signature, alice_public_key)
    if is_signature_valid:
        with open(ca_private_key_path, 'r') as f:
            ca_private_key = f.read()
        ca_signature = sign_hash(hash_obj, ca_private_key)
        print("CA signing document...")  # Added log
        embed_signature_in_pdf(input_pdf_path, ca_signature, output_pdf_path, '/CASignature')
        print("CA's signature process completed.")  # Added log
    else:
        print("CA could not verify Alice's signature.")