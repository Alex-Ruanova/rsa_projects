# ca.py

from alice import hash_pdf_content, sign_hash, embed_signature_in_pdf
import PyPDF2
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def extract_signature_from_pdf(pdf_path, signature_key):
    reader = PyPDF2.PdfReader(pdf_path)
    metadata = reader.metadata
    signature = metadata.get(signature_key)
    if signature:
        return eval(signature)
    return None


def verify_signature(hash_obj, signature, public_key):
    try:
        pkcs1_15.new(RSA.import_key(public_key)).verify(hash_obj, signature)
        print("The signature is valid.")
        return True
    except (ValueError, TypeError):
        print("The signature is not valid.")
        return False


def ca_verifies_and_signs_document(input_pdf_path, ca_private_key_path, alice_public_key_path, output_pdf_path):
    hash_obj = hash_pdf_content(input_pdf_path)
    alice_signature = extract_signature_from_pdf(input_pdf_path, '/AliceSignature')

    with open(alice_public_key_path, 'r') as f:
        alice_public_key = f.read()

    if verify_signature(hash_obj, alice_signature, alice_public_key):
        with open(ca_private_key_path, 'r') as f:
            ca_private_key = f.read()

        ca_signature = sign_hash(hash_obj, ca_private_key)
        embed_signature_in_pdf(input_pdf_path, ca_signature, output_pdf_path)
    else:
        print("CA could not verify Alice's signature.")

# ca_verifies_and_signs_document('signed_by_alice.pdf', 'ca_private.pem', 'alice_public.pem', 'signed_by_ca.pdf')
