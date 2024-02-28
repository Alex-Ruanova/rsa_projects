import datetime
import endesive
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend


# Step 1: Generate RSA Keys and Certificate for Alice
def generate_self_signed_cert(email, common_name, private_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())

    return cert


private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

cert = generate_self_signed_cert("alice@example.com", "Alice", private_key)

# Convert the certificate and private key to PEM format
cert_pem = cert.public_bytes(serialization.Encoding.PEM)
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=BestAvailableEncryption(b'mypassword'),
)


# Step 2: Digitally Sign the PDF
def sign_pdf(pdf_path, output_pdf_path, cert_pem, private_key_pem):
    dct = {
        "sigflags": 3,
        "sigpage": 0,
        "sigbutton": True,
        "contact": "alice@example.com",
        "location": "San Francisco",
        "signingdate": datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S+00\'00\''),
        "reason": "Signing the NDA",
        "certificate": cert_pem,
        "password": "mypassword",
    }
    with open(pdf_path, 'rb') as fp:
        pdf_bytes = fp.read()
        signed_pdf_bytes = endesive.pdf.cms.sign(pdf_bytes, dct, private_key_pem, cert_pem, [], 'sha256')

    with open(output_pdf_path, 'wb') as fp:
        fp.write(signed_pdf_bytes)


# Assuming 'NDA.pdf' is the PDF you want to sign
sign_pdf('NDA.pdf', 'NDA_signed.pdf', cert_pem, private_key_pem)

# Step 3: Verification
# Verification can be done using endesive's verify function or by opening the signed PDF in a PDF viewer
# that supports digital signatures (like Adobe Reader) and checking the signature properties.
