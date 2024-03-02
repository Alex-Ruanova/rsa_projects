from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

def hash_pdf_content(content, exclude_signature=False):
    if exclude_signature:
        signature_delimiter = b'--SIGNATURE--'
        delimiter_position = content.rfind(signature_delimiter)
        if delimiter_position != -1:
            content = content[:delimiter_position]
    print(f"Content read for hashing: {len(content)} bytes")
    hasher = SHA256.new(content)
    print(f"Document hashed, hash_obj: {hasher.hexdigest()}")
    return hasher

def sign_hash(hash_obj, private_key):
    signer = pkcs1_15.new(RSA.import_key(private_key))
    signature = signer.sign(hash_obj)
    print(f"Signature generated: {signature[:10]}... length: {len(signature)}")  # Log
    return signature


def alice_signs_document(content, private_key):
    print("Starting document signing process...")
    hash_obj = hash_pdf_content(content)
    signature = sign_hash(hash_obj, private_key)
    signed_content = content + b"--ALICESIGNATURE--" + signature
    print("Document signing process completed.")
    return signed_content
