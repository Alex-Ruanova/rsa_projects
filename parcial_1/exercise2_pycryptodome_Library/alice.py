from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import PyPDF2
import hashlib
def hash_pdf_content(pdf_path):
    with open(pdf_path, 'rb') as f:
        pdf_content = f.read()
    # Use hashlib to create the hash
    hasher = hashlib.sha256(pdf_content)
    print(f"PDF content read for hashing: {len(pdf_content)} bytes")  # Log the content size
    print(f"Document hashed, hash_obj: {hasher.hexdigest()}")  # Log the hash
    return hasher

def sign_hash(hash_obj, private_key):
    signer = pkcs1_15.new(RSA.import_key(private_key))
    signature = signer.sign(hash_obj)
    print(f"Signature generated: {signature[:10]}... length: {len(signature)}")  # Modified log
    return signature

def embed_signature_in_pdf(pdf_path, signature, output_pdf_path):
    reader = PyPDF2.PdfReader(pdf_path)
    writer = PyPDF2.PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    metadata = reader.metadata
    new_metadata = {**metadata, '/AliceSignature': str(signature)}
    writer.add_metadata(new_metadata)

    with open(output_pdf_path, 'wb') as f_out:
        writer.write(f_out)
    print("Signature embedded into metadata.")  # Added log

def alice_signs_document(pdf_path, private_key_path, output_pdf_path):
    print(f"Starting document signing process for: {pdf_path}")
    hash_obj = hash_pdf_content(pdf_path)
    with open(private_key_path, 'r') as f:
        private_key = f.read()

    signature = sign_hash(hash_obj, private_key)
    embed_signature_in_pdf(pdf_path, signature, output_pdf_path)
    print(f"Document signing process completed for: {pdf_path}")
