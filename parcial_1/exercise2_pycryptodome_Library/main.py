import alice
import ca
import bob
import key_manager

def main():
    alice_private_key, alice_public_key = key_manager.load_or_generate_keys('alice_private.pem', 'alice_public.pem')
    ca_private_key, ca_public_key = key_manager.load_or_generate_keys('ca_private.pem', 'ca_public.pem')

    with open('NDA.pdf', 'rb') as file:
        original_content = file.read()

    signed_content_by_alice = alice.alice_signs_document(original_content, alice_private_key)
    signed_content_by_ca = ca.ca_verifies_and_signs_document(signed_content_by_alice, ca_private_key, alice_public_key)
    bob.bob_verifies_document(signed_content_by_ca, alice_public_key, ca_public_key)

if __name__ == '__main__':
    main()
