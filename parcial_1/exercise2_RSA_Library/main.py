import rsa

# Generate RSA public and private keys
(public_key, private_key) = rsa.newkeys(1024)

# Save the public key
with open('public_key.pem', mode='wb') as pub_file:
    pub_file.write(public_key.save_pkcs1('PEM'))

# Save the private key
with open('private_key.pem', mode='wb') as priv_file:
    priv_file.write(private_key.save_pkcs1('PEM'))


# Load the RSA public and private keys
with open('public_key.pem', mode='rb') as pub_file:
    public_key = rsa.PublicKey.load_pkcs1(pub_file.read())

with open('private_key.pem', mode='rb') as priv_file:
    private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())

# Read the PDF file as bytes
pdf_file_path = 'NDA.pdf'
with open(pdf_file_path, 'rb') as file:
    pdf_content = file.read()

# Sign the PDF content
signature = rsa.sign(pdf_content, private_key, "SHA-256")

# Verify the signature
try:
    rsa.verify(pdf_content, signature, public_key)
    print("The signature is valid.")

except rsa.VerificationError:
    print("The signature is invalid.")
