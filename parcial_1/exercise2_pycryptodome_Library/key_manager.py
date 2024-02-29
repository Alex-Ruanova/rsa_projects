# key_manager.py

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
