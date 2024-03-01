import os
from Crypto.PublicKey import RSA

def generate_rsa_keys(key_size=1024):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_keys(private_key, public_key, private_key_filename, public_key_filename):
    with open(private_key_filename, 'wb') as prv_file:
        prv_file.write(private_key)
    with open(public_key_filename, 'wb') as pub_file:
        pub_file.write(public_key)

def load_or_generate_keys(private_key_filename, public_key_filename, key_size=1024):
    # Verifica si los archivos de llave ya existen
    if os.path.exists(private_key_filename) and os.path.exists(public_key_filename):
        # Carga las llaves existentes
        with open(private_key_filename, 'rb') as prv_file:
            private_key = prv_file.read()
        with open(public_key_filename, 'rb') as pub_file:
            public_key = pub_file.read()
    else:
        # Genera y guarda nuevas llaves si no existen
        private_key, public_key = generate_rsa_keys(key_size)
        save_keys(private_key, public_key, private_key_filename, public_key_filename)
    return private_key, public_key
