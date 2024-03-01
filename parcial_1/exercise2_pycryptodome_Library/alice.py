from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def hash_pdf_content(pdf_path, exclude_signature=False):
    with open(pdf_path, 'rb') as f:
        pdf_content = f.read()

    if exclude_signature:
        signature_delimiter = b'--SIGNATURE--'
        delimiter_position = pdf_content.rfind(signature_delimiter)
        if delimiter_position != -1:
            # Exclude the signature and delimiter from the content to be hashed
            pdf_content = pdf_content[:delimiter_position]

    print(f"PDF content read for hashing: {len(pdf_content)} bytes")
    hasher = SHA256.new(pdf_content)
    print(f"Document hashed, hash_obj: {hasher.hexdigest()}")
    return hasher


def sign_hash(hash_obj, private_key):
    signer = pkcs1_15.new(RSA.import_key(private_key))
    signature = signer.sign(hash_obj)
    print(f"Signature generated: {signature[:10]}... length: {len(signature)}")  # Log
    return signature


def append_signature_to_pdf(pdf_path, signature, output_pdf_path, signature_id):
    # Read the original PDF content
    with open(pdf_path, 'rb') as pdf_file:
        pdf_content = pdf_file.read()

    # Append the signature with a unique identifier
    with open(output_pdf_path, 'wb') as output_file:
        output_file.write(pdf_content)
        output_file.write(signature_id.encode())  # Convert identifier to bytes and append
        output_file.write(signature)

    # New log to show the document size after signature append
    print(f"{signature_id} appended to PDF file.")
    new_pdf_size = len(pdf_content) + len(signature_id.encode()) + len(signature)
    print(f"New document size after appending signature: {new_pdf_size} bytes")

    # Calculate and log the hash of the document after appending the signature
    with open(output_pdf_path, 'rb') as f:
        new_pdf_content = f.read()
    new_hasher = SHA256.new(new_pdf_content)
    print(f"Document hash after appending signature: {new_hasher.hexdigest()}")


def alice_signs_document(pdf_path, private_key_path, output_pdf_path):
    print(f"Starting document signing process for: {pdf_path}")  # Log
    hash_obj = hash_pdf_content(pdf_path)
    with open(private_key_path, 'r') as f:
        private_key = f.read()

    signature = sign_hash(hash_obj, private_key)
    # Include signature ID for Alice's signature
    append_signature_to_pdf(pdf_path, signature, output_pdf_path, "--ALICESIGNATURE--")
    print(f"Document signing process completed for: {pdf_path}")  # Log
