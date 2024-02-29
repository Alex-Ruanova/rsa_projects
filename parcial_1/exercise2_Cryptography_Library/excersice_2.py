from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import datetime
import endesive

# Generate private key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Generate a self-signed certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
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
    x509.BasicConstraints(ca=True, path_length=None), critical=True,
).sign(private_key, hashes.SHA256())

# Serialize private key and certificate
private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
certificate_bytes = cert.public_bytes(serialization.Encoding.PEM)

# Save them to disk
with open("private_key.pem", "wb") as f:
    f.write(private_key_bytes)
with open("certificate.pem", "wb") as f:
    f.write(certificate_bytes)


def sign_pdf(pdf_path, cert_path, key_path, output_pdf_path):
    dct = {
        "sigflags": 3,
        "sigpage": 0,
        "sigbutton": True,
        "contact": "email@example.com",
        "location": "Location",
        "signingdate": datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S+00\'00\''),
        "reason": "Signing the PDF",
        "signature": "Signature",
        "signaturebox": (0, 0, 100, 100),
    }
    with open(cert_path, "rb") as f:
        cert = f.read()
    with open(key_path, "rb") as f:
        key = f.read()
    with open(pdf_path, "rb") as f:
        pdf = f.read()

    datau = endesive.pdf.cms.sign(pdf, dct, key, cert, [], 'sha256')

    with open(output_pdf_path, "wb") as f:
        f.write(datau)


sign_pdf("NDA.pdf", "certificate.pem", "private_key.pem", "NDA_signed.pdf")