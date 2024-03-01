from alice import hash_pdf_content, sign_hash, embed_signature_in_pdf
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import fitz  # Importing fitz for handling PDF operations

def extract_signature_from_pdf(pdf_path, signature_key):
    doc = fitz.open(pdf_path)
    metadata = doc.metadata
    signature_hex = metadata.get(signature_key, '')
    if signature_hex:
        signature_bytes = bytes.fromhex(signature_hex)
        print(f"Extracted signature: {signature_bytes[:10]}... length: {len(signature_bytes)}")
        return signature_bytes
    else:
        print("No signature found in PDF metadata.")
        return None

def verify_signature(hash_obj, signature, public_key):
    if signature is None:
        print("Signature is None, cannot verify.")
        return False
    try:
        print(f"Hash object for verification: {hash_obj.hexdigest()}")
        verifier = pkcs1_15.new(RSA.import_key(public_key))
        verifier.verify(hash_obj, signature)
        print("The signature is valid.")
        return True
    except (ValueError, TypeError) as e:
        print(f"The signature is not valid. Error: {str(e)}")
        if signature:
            print(f"Signature for verification: {signature[:10]}... length: {len(signature)}")
        else:
            print("Signature is None.")
        return False

def embed_signature_in_pdf(pdf_path, signature, output_pdf_path, signature_key):
    doc = fitz.open(pdf_path)
    doc.metadata[signature_key] = signature.hex()  # Adjust to use hex encoding
    doc.save(output_pdf_path, incremental=True, encryption=fitz.PDF_ENCRYPT_KEEP)
    print("CA's signature embedded into PDF metadata.")

def ca_verifies_and_signs_document(input_pdf_path, ca_private_key_path, alice_public_key_path, output_pdf_path):
    print("CA starts verifying document...")
    hash_obj = hash_pdf_content(input_pdf_path)
    alice_signature = extract_signature_from_pdf(input_pdf_path, 'AliceSignature')
    if alice_signature is None:
        print("Failed to extract Alice's signature from the document. Aborting verification.")
        return  # Early return if Alice's signature is not found
    with open(alice_public_key_path, 'r') as f:
        alice_public_key = f.read()
    print(f"Using Alice's public key for verification: {alice_public_key[:50]}...")
    is_signature_valid = verify_signature(hash_obj, alice_signature, alice_public_key)
    if is_signature_valid:
        with open(ca_private_key_path, 'r') as f:
            ca_private_key = f.read()
        ca_signature = sign_hash(hash_obj, ca_private_key)
        print("CA signing document...")
        embed_signature_in_pdf(input_pdf_path, ca_signature, output_pdf_path, 'CASignature')
        print("CA's signature process completed.")
    else:
        print("CA could not verify Alice's signature.")
