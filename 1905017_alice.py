import socket
import importlib
import pickle
import binascii

module_name = '1905017_aes'
aes = importlib.import_module(module_name)

module_name = '1905017_ecc'
ecc = importlib.import_module(module_name)


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 8080)
server_socket.bind(server_address)
server_socket.listen(1)


print("ALICE: Waiting for BOB to connect.......")
connection, client_address = server_socket.accept()
print(f"ALICE: Connected to {client_address}")


#generate Diffie-hellman key
nbits = 128
alice_public_key_object, alice_private_key = ecc.generateECC_KeyPairs(None,nbits,None)
print("ALICE: Generating private-public key pairs")

#send public key to bob
serialized_alice_public_key_object = pickle.dumps(alice_public_key_object)
connection.sendall(serialized_alice_public_key_object)
print("ALICE: Sending public key of ALICE to BOB")

#rec bob's public key
serialized_bob_public_key_object = connection.recv(4096)
bob_public_key_object = pickle.loads(serialized_bob_public_key_object)
print("ALICE: Receiving public key of BOB")

#print(bob_public_key_object)

#generate shared key

shared_key = ecc.generateMainKey(bob_public_key_object,alice_private_key)
print(f"ALICE: Shared_key with BOB :{shared_key}")

# #inform bob that alice is ready
# connection.send(b"ALICE_READY")

msg = "Hello,Bob! Never Gonna Give you up."
byte_string = shared_key.to_bytes(16,byteorder='big')
shared_key_str = ''.join(chr(byte) for byte in byte_string)
print(f"shared key in string:{shared_key_str}")

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
plainText_str = msg
print("Plaintext")
print("In ASCII: " + plainText_str)
print("In HEX: ", end='')
plainText_grid_list =aes. string_to_grid_nl(plainText_str)
for each in plainText_grid_list:
    aes.print_grid_linear(each)
print()
print()
iv = aes.string_to_grid("this is iv")
ciphertext_str = key_obj_aes.encrypt(plainText_str, iv)
print("Ciphertext")
print("In ASCII: " + ciphertext_str)
print("In HEX: ", end='')
ciphertext_grid_list = aes.string_to_grid_nl(ciphertext_str)
for each in ciphertext_grid_list:
    aes.print_grid_linear(each)
print()
print()

#sending the ciphertext
serialized_ciphertext_str = pickle.dumps(ciphertext_str)
connection.sendall(serialized_ciphertext_str)

print()
print()
print("Ciphertext has been sent to BOB Successfully")
connection.close()
server_socket.close()


