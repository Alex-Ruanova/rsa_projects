# alice.py

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import PyPDF2


def hash_pdf_content(pdf_path):
    with open(pdf_path, 'rb') as f:
        pdf_content = f.read()
        hasher = SHA256.new(pdf_content)
    return hasher


def sign_hash(hash_obj, private_key):
    signer = pkcs1_15.new(RSA.import_key(private_key))
    signature = signer.sign(hash_obj)
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


def alice_signs_document(pdf_path, private_key_path, output_pdf_path):
    hash_obj = hash_pdf_content(pdf_path)
    with open(private_key_path, 'r') as f:
        private_key = f.read()

    signature = sign_hash(hash_obj, private_key)
    embed_signature_in_pdf(pdf_path, signature, output_pdf_path)


