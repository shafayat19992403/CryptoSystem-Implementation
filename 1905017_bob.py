import socket
import importlib
import pickle
import binascii

module_name = '1905017_aes'
aes = importlib.import_module(module_name)

module_name = '1905017_ecc'
ecc = importlib.import_module(module_name)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 8080)

print("BOB: Connecting to Alice......")
client_socket.connect(server_address)
print(f"BOB: Connected to Alice at {server_address}")

#rec alice's public key
serialized_alice_public_key_object = client_socket.recv(4096)
alice_public_key_object = pickle.loads(serialized_alice_public_key_object)
print("BOB: Received Public key of ALICE")

#print(alice_public_key_object)


#generate diffie-hellman
nbits=128
curve = alice_public_key_object['curve']
g_point = alice_public_key_object['g-point']
bob_public_key_object, bob_private_key = ecc.generateECC_KeyPairs(curve,nbits,g_point)
print("BOB: Generating public-private key pairs")

#send bob's public key to alice
serialized_bob_public_key_object = pickle.dumps(bob_public_key_object)
client_socket.sendall(serialized_bob_public_key_object)
print("BOB: Sending public key of BOB to ALICE")

#generate shared key
shared_key = ecc.generateMainKey(alice_public_key_object,bob_private_key)
print(f"BOB: Shared key with Alice: {shared_key}")

byte_string = shared_key.to_bytes(16,byteorder='big')
shared_key_str = ''.join(chr(byte) for byte in byte_string)
print(f"shared key in string:{shared_key_str}")


#rec the ciphertext
serialized_ciphertext_str = client_socket.recv(4096)
ciphertext_str = pickle.loads(serialized_ciphertext_str)
print("Ciphertext received Successfully")

print()
print()
print("Key")
print("In ASCII: " + shared_key_str)
print("In HEX: ", end='')
key_grid = aes.string_to_grid(shared_key_str)
aes.print_grid_linear(key_grid)
key_obj_aes = aes.AES(shared_key_str)
print()
print()

print("Ciphertext")
print("In ASCII: " + ciphertext_str)
print("In HEX: ", end='')
ciphertext_grid_list = aes.string_to_grid_nl(ciphertext_str)
for each in ciphertext_grid_list:
    aes.print_grid_linear(each)
print()
print()

iv = aes.string_to_grid("this is iv")
deciphered_text_str = key_obj_aes.decrypt(ciphertext_str, iv)
print("Deciphered Text")
print("In ASCII: " + deciphered_text_str)
print("In HEX: ", end='')
deciphered_text_grid_list = aes.string_to_grid_nl(deciphered_text_str)
for each in deciphered_text_grid_list:
    aes.print_grid_linear(each)
print()
print()

client_socket.close()


