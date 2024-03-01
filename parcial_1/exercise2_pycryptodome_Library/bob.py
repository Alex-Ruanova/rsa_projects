from alice import hash_pdf_content
from ca import extract_signature_from_pdf, verify_signature

def bob_verifies_document(pdf_path, alice_public_key_path, ca_public_key_path):
    print("Bob starts verifying document...")
    hash_obj = hash_pdf_content(pdf_path, exclude_signature=True)
    alice_signature = extract_signature_from_pdf(pdf_path, "--ALICESIGNATURE--")
    ca_signature = extract_signature_from_pdf(pdf_path, "--CASIGNATURE--")

    with open(alice_public_key_path, 'r') as f:
        alice_public_key = f.read()
    with open(ca_public_key_path, 'r') as f:
        ca_public_key = f.read()

    alice_verified = verify_signature(hash_obj, alice_signature, alice_public_key)
    ca_verified = verify_signature(hash_obj, ca_signature, ca_public_key)
    if alice_verified and ca_verified:
        print("Bob verified both signatures successfully.")
    else:
        print("Verification failed.")
