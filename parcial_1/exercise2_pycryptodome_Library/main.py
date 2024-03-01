import alice
import ca
import bob
import key_manager  # Import the key management module


def main():
    # Genera o carga las llaves para Alice
    alice_private_key, alice_public_key = key_manager.load_or_generate_keys('alice_private.pem', 'alice_public.pem')

    # Genera o carga las llaves para la CA
    ca_private_key, ca_public_key = key_manager.load_or_generate_keys('ca_private.pem', 'ca_public.pem')

    alice_private_key_path = 'alice_private.pem'
    alice_public_key_path = 'alice_public.pem'
    ca_private_key_path = 'ca_private.pem'
    ca_public_key_path = 'ca_public.pem'
    original_document = 'hola.txt'
    signed_by_alice = 'hola.txt'
    signed_by_ca = 'hola.txt'

    # Alice signs the document
    alice.alice_signs_document(original_document, alice_private_key_path, signed_by_alice)

    # CA verifies Alice's signature and signs the document
    ca.ca_verifies_and_signs_document(signed_by_alice, ca_private_key_path, alice_public_key_path, signed_by_ca)

    # Bob verifies both signatures
    bob.bob_verifies_document(signed_by_ca, alice_public_key_path, ca_public_key_path)

if __name__ == '__main__':
    main()