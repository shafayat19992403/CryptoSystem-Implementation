from BitVector import *
import time


class AESKey:
    def __init__(self, key) -> None:

        # round_constants = [10, 12, 14]
        # self.round = round_constants[min((len(key) - 1) // 8, 2)]

        self.time_key = None
        self.round = self.determine_rounds(key)
        self.key_in_string = key.ljust(16, '\0')[:16]
        self.key_in_matrix = string_to_grid(self.key_in_string)
        self.round_key = [self.key_in_matrix]

        #print(f"Rounds: {self.round}")
        self.calculate_round_keys()

    def determine_rounds(self, key):
        key_length = len(key)

        if key_length <= 16 :
            return 10
        elif 16 < key_length <= 24 :
            return 12
        else:
            return 14

    def calculate_round_keys(self):
        start_time = time.time()

        nth_round = 1
        while nth_round<=self.round+1:
            self.round_key.append(self.generate_round_key(nth_round))
            nth_round+=1

        end_time = time.time()
        self.time_key = end_time - start_time


    def g_func(self, word, n_round):
        new_word = word[1:] + word[:1]  # Circular left shift

        # Substitute
        temp_word=[]
        for word in new_word:
            t = Sbox[word]
            temp_word.append(t)

        new_word = temp_word

        temp_word=[]
        for i in range(4):
            t = new_word[i] ^ RoundConst[n_round][i]
            temp_word.append(t)

        new_word = temp_word

        return new_word


    def generate_round_key(self, n_round):
        old_cols = [[self.round_key[n_round - 1][i][j] for i in range(4)] for j in range(4)]
        g_old_3_mine = self.g_func(old_cols[-1],n_round)

        new_cols = []
        temp = g_old_3_mine
        for i in range(4):
            temp = [old_cols[i][k] ^ temp[k] for k in range(4)]
            new_cols.append(temp)

        return [[new_cols[i][k] for i in range(4)] for k in range(4)]


class AES:
    def __init__(self, key)-> None:
        self.aes_key = AESKey(key)
        self.time_enc = 0
        self.time_dec = 0

    def transformations(self,block,n,temp_key):
        if n == 0:
            block = xor_grid(block, temp_key)
        elif 0< n <= 9:
            block = substitute_bytes(block)
            block = shift_rows(block, "left")
            block = mix_columns(block, False)
            block = xor_grid(block, temp_key)
        else:
            block = substitute_bytes(block)
            block = shift_rows(block, "left")
            block = xor_grid(block, temp_key)

        return block


    def encrypt_block(self,block):

        for round in range(0,11):
            temp_key = self.aes_key.round_key[round]
            block = self.transformations(block,round,temp_key)

        return block


    def block_slicer(self,msg):
        block_list = [msg[i:i + 16] for i in range(0, len(msg), 16)]

        length_of_last_block = len(block_list[-1])
        if length_of_last_block != 16:
            block_list[-1] = block_list[-1].ljust(16, '\0')

        return block_list

    def encrypt(self,msg,iv):
        start = time.time()
        block_list = self.block_slicer(msg)

        ret=[]
        temp = iv
        for block in block_list:
            block = string_to_grid(block)
            block = xor_grid(block,temp)
            enc_block = self.encrypt_block(block)
            ret.append(enc_block)
            temp = enc_block

        string_ret = ""
        for str_block in ret:
            temp_ret = grid_to_string(str_block)
            string_ret = string_ret + temp_ret

        # ret = "".join([grid_to_string(i) for i in ret])

        end = time.time()
        self.time_enc = (end - start)
        return string_ret
        #return ret


    def InverseTransform(self, block, n, temp_key):
        if n==10 :
            block = xor_grid(block, temp_key)
            block = shift_rows(block, "right")
            block = substitute_bytes(block, True)
        elif n==0:
            block = xor_grid(block, temp_key)
        elif 1 <= n < 10:
            block = xor_grid(block, temp_key)
            block = mix_columns(block, True)
            block = shift_rows(block, "right")
            block = substitute_bytes(block, True)
        return block

    def decrypt_block(self, cipher):

        temp_key = self.aes_key.round_key[10]
        block = self.InverseTransform(cipher,10,temp_key)
        for round in range(1,10):
            temp_key=self.aes_key.round_key[10 - round]
            block = self.InverseTransform(block,10-round,temp_key)

        temp_key=self.aes_key.round_key[0]
        block= self.InverseTransform(block, 0, temp_key)

        return block

    def decrypt(self,cipher,iv):
        start = time.time()
        block_list = self.block_slicer(cipher)
        grid_list = []
        for block in block_list:
            temp = string_to_grid(block)
            temp2 = temp
            temp = self.decrypt_block(temp)
            temp = xor_grid(temp,iv)
            grid_list.append(temp)
            iv = temp2


        text = ""
        for grid in grid_list:
            temp = grid_to_string(grid)
            text = text + temp

        text = text.rstrip('\x00')
        end = time.time()
        self.time_dec = (end - start)
        return text




RoundConst = [
    [0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1B, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00],
    [0x6C, 0x00, 0x00, 0x00],
    [0xD8, 0x00, 0x00, 0x00],
    [0xAB, 0x00, 0x00, 0x00],
    [0x4D, 0x00, 0x00, 0x00],
    [0x9A, 0x00, 0x00, 0x00]
]

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]



def string_to_grid(block):
    block = block.ljust(16, '\0')
    return [
        [ord(block[0]), ord(block[4]), ord(block[8]), ord(block[12])],
        [ord(block[1]), ord(block[5]), ord(block[9]), ord(block[13])],
        [ord(block[2]), ord(block[6]), ord(block[10]), ord(block[14])],
        [ord(block[3]), ord(block[7]), ord(block[11]), ord(block[15])]
    ]


def string_to_grid_nl(block):
    aes_slicer_obj = AES("slicer")
    block_list = aes_slicer_obj.block_slicer(block)
    grid_list=[]
    for each in block_list:
        grid = string_to_grid(each)
        grid_list.append(grid)

    return grid_list

def grid_to_string(grid):
    str_res = ""
    for col in range(4):
        for row in range(4):
            str_res = str_res + chr(grid[row][col])
    return str_res


def print_list(arr):
    print(" ".join(f"0x{each:x}" for each in arr))


def print_grid(grid):
    for row in grid:
        print_list(row)
    print()


def print_grid_linear(grid):
    num_rows = len(grid)
    num_cols = len(grid[0])

    # Transpose the matrix
    transposed_grid = [[grid[row][col] for row in range(num_rows)] for col in range(num_cols)]

    for each_row in transposed_grid:
        for element in each_row:
            if element == 0:
                print(f"00",end=' ')
            else:
                print(f"{element:x}",end=' ')

    print()


def xor_grid(first, second):
    return [[a ^ b for a, b in zip(row_first, row_second)] for row_first, row_second in zip(first, second)]


def substitute_bytes(block, is_inverse=False):
    new_grid = [[0 for _ in range(4)] for _ in range(4)]
    substitution_table = InvSbox if is_inverse else Sbox

    for row in range(4):
        for col in range(4):
            new_grid[row][col] = substitution_table[block[row][col]]

    return new_grid


def shift_rows(block, direction='left'):
    new_grid = [[0 for _ in range(4)] for _ in range(4)]

    for row in range(4):
        if direction == 'left':
            new_grid[row] = block[row][row:] + block[row][:row]
        elif direction == 'right':
            new_grid[row] = block[row][-row:] + block[row][:-row]
        else:
            raise ValueError("Invalid direction. Use 'left' or 'right'.")

    return new_grid


# def mix_columns(block, inverse=False):
#     aes_mod = BitVector(bitstring='100011011')
#     new_grid = [[0] * 4 for _ in range(4)]
#     mixer_matrix = InvMixer if inverse else Mixer
#
#     for row in range(4):
#         for col in range(4):
#             for item in range(4):
#                 bv_val = BitVector(intVal=block[item][col])
#                 bv_out = mixer_matrix[row][item].gf_multiply_modular(bv_val, aes_mod, 8)
#                 new_grid[row][col] ^= bv_out.intValue()
#
#     return new_grid

def mix_columns(block, inverse=False):
    aes_mod = BitVector(bitstring='100011011')
    new_grid = [[0] * 4 for _ in range(4)]
    mixer_matrix = InvMixer if inverse else Mixer

    row = 0
    while True:
        if row>=4:
            break
        for col in range(4):
            item = 0
            while True:
                if item >= 4:
                    break
                block_value = block[item][col]
                bitVector_value = BitVector(intVal=block_value)
                bitVector_out = mixer_matrix[row][item].gf_multiply_modular(bitVector_value, aes_mod, 8)
                new_grid[row][col] ^= bitVector_out.intValue()
                item = item + 1
        row = row + 1


    return new_grid

# key_str = "BUET CSE19 Batch"
# print("Key")
# print("In ASCII: "+key_str)
# print("In HEX: ",end='')
# key_grid = string_to_grid(key_str)
# print_grid_linear(key_grid)
# key_obj_aes = AES(key_str)
# print()
# print()
# plainText_str = "Never Gonna Give you up"
# print("Plaintext")
# print("In ASCII: "+plainText_str)
# print("In HEX: ",end='')
# plainText_grid_list = string_to_grid_nl(plainText_str)
# for each in plainText_grid_list:
#     print_grid_linear(each)
# print()
# print()
#
# iv = string_to_grid("this is iv")
# ciphertext_str = key_obj_aes.encrypt(plainText_str,iv)
# print("Ciphertext")
# print("In ASCII: "+ciphertext_str)
# print("In HEX: ",end='')
# ciphertext_grid_list = string_to_grid_nl(ciphertext_str)
# for each in ciphertext_grid_list:
#     print_grid_linear(each)
# print()
# print()
#
# deciphered_text_str = key_obj_aes.decrypt(ciphertext_str,iv)
# print("Deciphered Text")
# print("In ASCII: "+deciphered_text_str)
# print("In HEX: ",end='')
# deciphered_text_grid_list = string_to_grid_nl(deciphered_text_str)
# for each in deciphered_text_grid_list:
#     print_grid_linear(each)
# print()
# print()
# print("Execution Details:")
# print(f"Key Schedule Time: {key_obj_aes.aes_key.time_key * 1000} ms")
# print(f"Encryption Time: {key_obj_aes.time_enc * 1000} ms")
# print(f"Decryption Time: {key_obj_aes.time_dec * 1000} ms")

