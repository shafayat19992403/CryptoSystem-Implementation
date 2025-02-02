import importlib

module_name = '1905017_aes'
module = importlib.import_module(module_name)


key_str = "BUET CSE19 Batch"
print("Key")
print("In ASCII: " + key_str)
print("In HEX: ", end='')
key_grid = module.string_to_grid(key_str)
module.print_grid_linear(key_grid)
key_obj_aes = module.AES(key_str)
print()
print()
plainText_str = "Never Gonna Give you up"
print("Plaintext")
print("In ASCII: " + plainText_str)
print("In HEX: ", end='')
plainText_grid_list =module. string_to_grid_nl(plainText_str)
for each in plainText_grid_list:
    module.print_grid_linear(each)
print()
print()

iv = module.string_to_grid("this is iv")
ciphertext_str = key_obj_aes.encrypt(plainText_str, iv)
print("Ciphertext")
print("In ASCII: " + ciphertext_str)
print("In HEX: ", end='')
ciphertext_grid_list = module.string_to_grid_nl(ciphertext_str)
for each in ciphertext_grid_list:
    module.print_grid_linear(each)
print()
print()

deciphered_text_str = key_obj_aes.decrypt(ciphertext_str, iv)
print("Deciphered Text")
print("In ASCII: " + deciphered_text_str)
print("In HEX: ", end='')
deciphered_text_grid_list = module.string_to_grid_nl(deciphered_text_str)
for each in deciphered_text_grid_list:
    module.print_grid_linear(each)
print()
print()
print("Execution Details:")
print(f"Key Schedule Time: {key_obj_aes.aes_key.time_key * 1000} ms")
print(f"Encryption Time: {key_obj_aes.time_enc * 1000} ms")
print(f"Decryption Time: {key_obj_aes.time_dec * 1000} ms")
