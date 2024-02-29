# bob.py

from ca import extract_signature_from_pdf, verify_signature
from alice import hash_pdf_content


def bob_verifies_document(pdf_path, alice_public_key_path, ca_public_key_path):
    hash_obj = hash_pdf_content(pdf_path)
    alice_signature = extract_signature_from_pdf(pdf_path, '/AliceSignature')
    ca_signature = extract_signature_from_pdf(pdf_path, '/CASignature')

    with open(alice_public_key_path, 'r') as f:
        alice_public_key = f.read()
    with open(ca_public_key_path, 'r') as f:
        ca_public_key = f.read()

    if verify_signature(hash_obj, alice_signature, alice_public_key) and verify_signature(hash_obj, ca_signature,
                                                                                          ca_public_key):
        print("Bob verified both signatures successfully.")
    else:
        print("Verification failed.")

# bob_verifies_document('signed_by_ca.pdf', 'alice_public.pem', 'ca_public.pem')
