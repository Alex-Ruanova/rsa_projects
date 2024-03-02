from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import textwrap

# Función para dividir el mensaje en bloques de 128 caracteres sin cortar palabras
def divide_message_into_blocks(message, block_size=128):
    message_blocks = textwrap.wrap(message, block_size, break_long_words=False)
    for index in range(len(message_blocks) - 1):
        if not message_blocks[index].endswith(' ') and not message_blocks[index+1].startswith(' '):
            last_space_index = message_blocks[index].rfind(' ')
            message_blocks[index+1] = message_blocks[index][last_space_index+1:] + ' ' + message_blocks[index+1]
            message_blocks[index] = message_blocks[index][:last_space_index]
    print(f"Dividido en {len(message_blocks)} bloques.")
    return message_blocks

# Función para reconstruir el mensaje a partir de bloques descifrados
def reconstruct_message_from_blocks(blocks):
    reconstructed_message = ''
    for block in blocks:
        reconstructed_message += block if block.endswith(' ') or block.endswith('.') else block + ' '
    return reconstructed_message.strip()

# Generar un par de claves RSA
rsa_key_pair = RSA.generate(2048)
private_key = rsa_key_pair.export_key()
public_key = rsa_key_pair.publickey().export_key()
print("Claves RSA generadas correctamente.")

# Mensaje original
original_message = """En un lugar de la Mancha, de cuyo nombre no quiero acordarme, no ha mucho tiempo que vivía un hidalgo de los de lanza en astillero, adarga antigua, rocín flaco y galgo corredor. Una olla de algo más vaca que carnero, salpicón las más noches, duelos y quebrantos los sábados, lentejas los viernes, algún palomino de añadidura los domingos, consumían las tres partes de su hacienda. El resto della concluían sayo de velarte, calzas de velludo para las fiestas, con sus pantuflos de lo mismo, y los días de entresemana se honraba con su vellorí de lo más fino. Tenía en su casa una ama que pasaba de los cuarenta, y una sobrina que no llegaba a los veinte, y un mozo de campo y plaza, que así ensillaba el rocín como tomaba la podadera. Frisaba la edad de nuestro hidalgo con los cincuenta años; era de complexión recia, seco de carnes, enjuto de rostro, gran madrugador y amigo de la caza. Quieren decir que tenía el sobrenombre de Quijada, o Quesada, que en esto hay alguna diferencia en los autores que deste caso escriben; aunque, por conjeturas ve"""

# Dividir el mensaje en bloques
message_blocks = divide_message_into_blocks(original_message)
print("Mensaje dividido en bloques para cifrado.")

# Cifrar cada bloque con la clave pública
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
encrypted_blocks = [cipher_rsa.encrypt(block.encode('utf-8')) for block in message_blocks]
print("Bloques cifrados con la clave pública.")

# Descifrar cada bloque con la clave privada
decrypt_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
decrypted_blocks = [decrypt_rsa.decrypt(block).decode('utf-8') for block in encrypted_blocks]
print("Bloques descifrados con la clave privada.")

# Reconstruir el mensaje descifrado
reconstructed_message = reconstruct_message_from_blocks(decrypted_blocks)
print("Mensaje reconstruido a partir de los bloques descifrados.")

# Verificar que el mensaje reconstruido coincide con el mensaje original
message_integrity_check = original_message == reconstructed_message

# Generar el hash del mensaje original y del reconstruido
hash_original_message = SHA256.new(original_message.encode('utf-8')).hexdigest()
hash_reconstructed_message = SHA256.new(reconstructed_message.encode('utf-8')).hexdigest()

# Verificar que los hashes coinciden
hashes_match_check = hash_original_message == hash_reconstructed_message

# Resultados
print("-----------------------------------------------------------------")
print("Resultados de la verificación")
print("-----------------------------------------------------------------")
print(f"Mensaje original: {original_message}")
print(f"Mensaje reconstruido: {reconstructed_message}")
print()
print(f"Los mensajes son iguales: {message_integrity_check}")
print("-----------------------------------------------------------------")
print(f"Hash del mensaje original: {hash_original_message}")
print(f"Hash del mensaje reconstruido: {hash_reconstructed_message}")
print()
print(f"Los hashes coinciden: {hashes_match_check}")
print("-----------------------------------------------------------------")
