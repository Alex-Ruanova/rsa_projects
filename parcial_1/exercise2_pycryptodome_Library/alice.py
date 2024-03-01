from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import fitz

def hash_pdf_content(pdf_path):
    with open(pdf_path, 'rb') as f:
        pdf_content = f.read()
        print(f"PDF content read for hashing: {len(pdf_content)} bytes")  # Added log
        hasher = SHA256.new(pdf_content)
    print(f"Document hashed, hash_obj: {hasher.hexdigest()}")
    return hasher

def sign_hash(hash_obj, private_key):
    signer = pkcs1_15.new(RSA.import_key(private_key))
    signature = signer.sign(hash_obj)
    print(f"Signature generated: {signature[:10]}... length: {len(signature)}")  # Modified log
    return signature

def embed_signature_in_pdf(pdf_path, signature, output_pdf_path):
    doc = fitz.open(pdf_path)
    doc.metadata['AliceSignature'] = signature.hex()  # Correct key used here
    doc.save(output_pdf_path, incremental=True, encryption=fitz.PDF_ENCRYPT_KEEP)
    print("Signature embedded into PDF metadata.")
    doc.close()  # Close the document right after saving to ensure changes are written

    # Quick read-back test
    test_doc = fitz.open(output_pdf_path)
    test_metadata = test_doc.metadata
    test_signature_hex = test_metadata.get('AliceSignature', None)  # Correct key used here
    if test_signature_hex:
        print(f"Immediate read-back test successful, signature: {test_signature_hex[:10]}...")
    else:
        print("Immediate read-back test failed, no signature found.")
    test_doc.close()


def alice_signs_document(pdf_path, private_key_path, output_pdf_path):
    print(f"Starting document signing process for: {pdf_path}")
    hash_obj = hash_pdf_content(pdf_path)
    with open(private_key_path, 'r') as f:
        private_key = f.read()

    signature = sign_hash(hash_obj, private_key)
    embed_signature_in_pdf(pdf_path, signature, output_pdf_path)
    print(f"Document signing process completed for: {pdf_path}")
