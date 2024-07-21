import constant as Const
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
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)

Inv_Sbox = (
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
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
)

# Define the MixColumnMatrix as an array of lists.
MixColumnMatrix = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]

Inv_MixColumnMatrix = [
    [0x0E, 0x0B, 0x0D, 0x09],
    [0x09, 0x0E, 0x0B, 0x0D],
    [0x0D, 0x09, 0x0E, 0x0B],
    [0x0B, 0x0D, 0x09, 0x0E]
]

RC = [
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1B,
    0x36,
      ]



def handle_input(input_string):
    # Ensure the length is exactly 16 characters
    if len(input_string) == 16:
        return [input_string]  # Return a list with the original string as a single block
    elif len(input_string) < 16:
        # Add 'A' only if the length is shorter than 16
        input_string += 'A' * (16 - len(input_string))
        return [input_string]  # Return a list with the modified string as a single block
    else:
        # Divide the string into blocks of 16 characters
        blocks = [input_string[i:i + 16] for i in range(0, len(input_string), 16)]

        # Pad the last block with 'A' only if its length is shorter than 16
        last_block_index = len(blocks) - 1
        if len(blocks[last_block_index]) < 16:
            blocks[last_block_index] += 'A' * (16 - len(blocks[last_block_index]))

        return blocks  # Return a list with the resulting blocks


def handle_key(Key):
    if len(Key) == 16:
        return True  # Key is exactly 16 characters long
    elif len(Key) < 16:
        print("Error: The length of the Key is shorter than 16 characters. Please enter exactly 16 characters.")
    else:
        print("Error: The length of the Key is longer than 16 characters. Please enter exactly 16 characters.")

    return False  # Key is not exactly 16 characters long


def string_to_hexa(input_string):
    hex_result = ""
    for char in input_string:
        hex_result += format(ord(char), '02x')
    return hex_result


def hexa_to_string(hex_input):
    string_result = ""
    for i in range(0, len(hex_input), 2):
        hex_char = hex_input[i:i + 2]
        string_result += chr(int(hex_char, 16))
    return string_result


def form_matrix(hex_string):
    matrix = [[0] * 4 for _ in range(4)]  # Initialize a 4x4 State_matrix with zeros

    for col in range(4):
        for Row in range(4):
            # Extract two digits from the hexadecimal string and assign them to the State_matrix
            matrix[Row][col] = hex_string[col * 8 + Row * 2: col * 8 + Row * 2 + 2]

    return matrix


# Define a function to create a string from the Cipher_text list
def form_string(Cipher_text):
    # Initialize the hexadecimal string for each Block
    hex_string = ""
    # Loop over each Block in the Cipher_text list
    for Block in Cipher_text:
        # Loop over each column and row in the Block
        for j in range(4):
            for i in range(4):
                # Concatenate the hexadecimal values into a string
                hex_string += Block[i][j]
    # Return the output string
    return hex_string


def key_additions(State_matrix, Subkey):
    result_matrix = [[0] * 4 for _ in range(4)]  # Initialize a 4x4 State_matrix with zeros

    for i in range(4):
        for j in range(4):
            #Perform XOR for each corresponding byte in hexadecimal representation
            result_matrix[i][j] = format(int(State_matrix[i][j], 16) ^ int(Subkey[i][j], 16), '02x')

    return result_matrix


def byte_substitution(State_matrix):
    if len(State_matrix[0]) == 4:  # Check if the matrix is 4x4 to use in normal rounds.
        result_matrix = [[0] * 4 for _ in range(4)]  # Initialize a 4x4 matrix with zeros

        for i in range(4):
            for j in range(4):
                Row = int(State_matrix[i][j][0], 16)
                col = int(State_matrix[i][j][1], 16)
                result_matrix[i][j] = format(Const.Sbox[Row * 16 + col], '02x')

    elif len(State_matrix[0]) == 1:  # Check if the matrix is 4x1 to use in "G function" in key schedule.
        result_matrix = [0] * 4  # Initialize a 4x1 matrix with zeros

        for i in range(4):
            Row = int(State_matrix[i][0][0], 16)
            col = int(State_matrix[i][0][1], 16)
            result_matrix[i] = format(Const.Sbox[Row * 16 + col], '02x')

    else:
        # Handle the case when the matrix size is neither 4x4 nor 4x1
        return None

    return result_matrix


def inv_byte_substitution(State_matrix):
    if len(State_matrix[0]) == 4:  # Check if the matrix is 4x4
        result_matrix = [[0] * 4 for _ in range(4)]  # Initialize a 4x4 matrix with zeros

        for i in range(4):
            for j in range(4):
                Row = int(State_matrix[i][j][0], 16)
                col = int(State_matrix[i][j][1], 16)
                result_matrix[i][j] = format(Const.Inv_Sbox[Row * 16 + col], '02x')

    elif len(State_matrix[0]) == 1:  # Check if the matrix is 4x1
        result_matrix = [0] * 4  # Initialize a 4x1 matrix with zeros

        for i in range(4):
            Row = int(State_matrix[i][0][0], 16)
            col = int(State_matrix[i][0][1], 16)
            result_matrix[i] = format(Const.Inv_Sbox[Row * 16 + col], '02x')

    else:
        # Handle the case when the matrix size is neither 4x4 nor 4x1
        return None

    return result_matrix


def shift_rows(State_matrix):
    result_matrix = [[0] * 4 for _ in range(4)]  # Initialize a 4x4 State_matrix with zeros

    for i in range(4):
        # Perform row shifts based on the row index
        result_matrix[i] = State_matrix[i][i:] + State_matrix[i][:i]

    return result_matrix


def inv_shift_rows(State_matrix):
    result_matrix = [[0] * 4 for _ in range(4)]  # Initialize a 4x4 State_matrix with zeros

    for i in range(4):
        # Perform row shifts based on the row index
        result_matrix[i] = State_matrix[i][-i:] + State_matrix[i][:-i]

    return result_matrix


# Define a function to multiply two bytes in GF(2^8)
def gf_mult(MixColumn_matrix_row, State_matrix_column):
    # Initialize the result
    mult_result = 0
    # Loop over the bits of MixColumn_matrix_row
    for i in range(8):
        # If the i-th bit of MixColumn_matrix_row is 1, add State_matrix_column to the result
        if MixColumn_matrix_row & (1 << i):
            mult_result ^= State_matrix_column
        # If the most significant bit of State_matrix_column is 1, XOR with the irreducible polynomial
        if State_matrix_column & 0x80:
            State_matrix_column = (State_matrix_column << 1) ^ 0x11b  # The irreducible polynomial for GF(2^8).
        # Otherwise, just shift State_matrix_column left by one bit
        else:
            State_matrix_column <<= 1
    # Return the result
    return mult_result


# Define a function to perform the MixColumns operation
def mix_columns(State_matrix):
    # Initialize the output matrix (4*4 matrix with zeros)
    result_matrix = [[0 for _ in range(4)] for _ in range(4)]

    # Reformat the Constant MixColumnMatrix for MixColumns
    Reformat_MixColumnMatrix = [[format(x, '02x') for x in Row] for Row in Const.MixColumnMatrix]

    # Loop over the columns of the State_matrix matrix
    for j in range(4):
        # Loop over the rows of the MixColumn matrix
        for i in range(4):
            # Initialize the output element
            result_matrix[i][j] = 0

            # Perform matrix multiplication with the mix_matrix and the state matrix
            for k in range(4):
                # Use the gf_mult function to multiply two bytes in GF(2^8)     gf_mult(MixColumn_matrix_row, State_matrix_column)
                result_matrix[i][j] ^= gf_mult(int(Reformat_MixColumnMatrix[i][k], 16), int(State_matrix[k][j], 16))

            # Convert the result to hexadecimal string format
            result_matrix[i][j] = format(result_matrix[i][j], '02x')

    # Return the output matrix
    return result_matrix


def inv_mix_columns(State_matrix):
    # Initialize the output matrix (4*4 matrix with zeros)
    result_matrix = [[0 for _ in range(4)] for _ in range(4)]

    # Reformat the Constant MixColumnMatrix for MixColumns
    Reformat_MixColumnMatrix = [[format(x, '02x') for x in Row] for Row in Const.Inv_MixColumnMatrix]

    # Loop over the columns of the State_matrix matrix
    for j in range(4):
        # Loop over the rows of the MixColumn matrix
        for i in range(4):
            # Initialize the output element
            result_matrix[i][j] = 0

            # Perform matrix multiplication with the mix_matrix and the state matrix
            for k in range(4):
                # Use the gf_mult function to multiply two bytes in GF(2^8)     gf_mult(MixColumn_matrix_row, State_matrix_column)
                result_matrix[i][j] ^= gf_mult(int(Reformat_MixColumnMatrix[i][k], 16), int(State_matrix[k][j], 16))

            # Convert the result to hexadecimal string format
            result_matrix[i][j] = format(result_matrix[i][j], '02x')

    # Return the output matrix
    return result_matrix


def xor_array(array1, array2):
    result_array = [0] * 4  # Initialize a 4x1 array with zeros

    for i in range(4):
        # Convert hexadecimal strings to integer values
        byte1 = int(array1[i], 16)
        byte2 = int(array2[i], 16)

        # Perform XOR operation
        result_byte = byte1 ^ byte2

        # Convert the result back to a hexadecimal string
        result_array[i] = format(result_byte, '02x')

    return result_array


def g_func(Last_W, Round_Number):
    # Step 1: Shift to the left by one byte
    shifted_array = Last_W[1:] + [Last_W[0]]

    # Step 2: Byte-wise S-Box Substitution
    substituted_array = byte_substitution([[x] for x in shifted_array])

    # Step 3: XOR with the value of RC[Round_Number]
    rc_value = Const.RC[Round_Number - 1]
    XOR_result = [format(int(substituted_array[0], 16) ^ rc_value, '02x')]

    # Step 4: Append the remaining three bytes of the substituted_array
    result_array = XOR_result + substituted_array[1:]

    return result_array


def key_schedule(key_hexa):
    # Initialize the key matrix from the provided key_hexa
    key_matrix = form_matrix(key_hexa)

    # Initialize the list to store the 11 subkeys
    subkeys = [key_matrix]

    # First Subkey (Round 0)

    # Generate subkeys for Rounds 1 to 10
    for round_num in range(1, 11):
        # Get the last W of the previous Subkey
        last_w = subkeys[-1][-1]

        # Generate the new W for the current Subkey using g_func
        new_w = g_func(last_w, round_num)

        # XOR the new W with the first W of the previous Subkey
        xor_result1 = xor_array(subkeys[-1][0], new_w)
        # XOR the result with the second W of the previous Subkey
        xor_result2 = xor_array(subkeys[-1][1], xor_result1)
        # XOR the result with the third W of the previous Subkey
        xor_result3 = xor_array(subkeys[-1][2], xor_result2)
        # XOR the result with the fourth W of the previous Subkey
        xor_result4 = xor_array(subkeys[-1][3], xor_result3)

        # Create the new Subkey by replacing the W values
        new_subkey = [xor_result1, xor_result2, xor_result3, xor_result4]

        # Append the new Subkey to the list
        subkeys.append(new_subkey)

    return subkeys


def reverse_key(arr):   # Reverse array of lists.
    return arr[::-1]


def encryption(Plain_text, Key):
    plain_text_hexa = string_to_hexa(Plain_text)
    key_hexa = string_to_hexa(Key)

    plain_text_matrix = form_matrix(plain_text_hexa)
    subkeys = key_schedule(key_hexa)

    key_addition = key_additions(plain_text_matrix, subkeys[0])  # Initial Key Addition (0)

    for i in range(9):  # (1:9)
        byte_sub = byte_substitution(key_addition)  # Byte Substitution layer

        # Diffusion layer
        shift_row = shift_rows(byte_sub)    # Shift Rows Sublayer
        mix_column = mix_columns(shift_row)     # Mix Columns Sublayer

        key_addition = key_additions(mix_column, subkeys[i+1])  # Round Key Addition (1:9)

    byte_sub = byte_substitution(key_addition)

    shift_row = shift_rows(byte_sub)

    key_addition = key_additions(shift_row, subkeys[10])  # Final Key Addition (10)

    return key_addition, subkeys


def decryption(Cipher_text, Subkey_rounds):
    cipher_text_hexa = string_to_hexa(Cipher_text)
    cipher_text_matrix = form_matrix(cipher_text_hexa)

    key_addition = key_additions(cipher_text_matrix, Subkey_rounds[0])  # Initial Key Addition (0)
    inv_shift_row = inv_shift_rows(key_addition)
    inv_byte_sub = inv_byte_substitution(inv_shift_row)

    for i in range(9):  # (1:9)

        key_addition = key_additions(inv_byte_sub, Subkey_rounds[i + 1])  # Round Key Addition (1:9)

        # Diffusion layer
        inv_mix_column = inv_mix_columns(key_addition)  # Mix Columns Sublayer
        inv_shift_row = inv_shift_rows(inv_mix_column)  # Shift Rows Sublayer

        inv_byte_sub = inv_byte_substitution(inv_shift_row)  # Byte Substitution layer

    key_addition = key_additions(inv_byte_sub, Subkey_rounds[10])  # Final Key Addition (10)

    return key_addition


if __name__ == "__main__":
    plain_text = input('Please, Enter the Plain text: ')
    handled_plain_text = handle_input(plain_text)

    key = input('Please, Enter a valid Key (Length should be exactly 16 characters.): ')

    while not handle_key(key):
        key = input('Please, Enter a valid Key (Length should be exactly 16 characters.): ')

    print('\r----------------------------------------ENCRYPTION----------------------------------------\r')

    subkey_rounds = []  # Subkeys for all rounds.
    cipher_text = []  # Initialize Cipher_text as a list
    for idx, block in enumerate(handled_plain_text):
        encrypted_block, subkey_rounds = encryption(block, key)
        cipher_text.append(encrypted_block)

        print(f'Block {idx + 1}:')
        for row in encrypted_block:
            print(row)
        print()

    hexa_cipher_text = form_string(cipher_text)
    print(f'Hexadecimal Cipher Text: {hexa_cipher_text}')

    string_cipher_text = hexa_to_string(hexa_cipher_text)
    print(f'String Cipher Text: {string_cipher_text}')

    print('\r----------------------------------------DECRYPTION----------------------------------------\r')

    plain_text = []  # Initialize Cipher_text as a list
    rev_subkey_rounds = reverse_key(subkey_rounds)

    handled_cipher_text = handle_input(string_cipher_text)
    for idx, block in enumerate(handled_cipher_text):
        decrypted_block = decryption(block, rev_subkey_rounds)
        plain_text.append(decrypted_block)

        print(f'Block {idx + 1}:')
        for row in decrypted_block:
            print(row)
        print()

    hexa_plain_text = form_string(plain_text)
    print(f'Hexadecimal Cipher Text: {hexa_plain_text}')

    string_plain_text = hexa_to_string(hexa_plain_text)
    print(f'String Cipher Text: {string_plain_text}')
