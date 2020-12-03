import des_test_data
import function_permutation_tables
import key_permutation_tables
import sbox_tables


def _add_padding(message):
    byt_cnt = 8 - (len(message) % 8)
    padding = byt_cnt * chr(byt_cnt)
    message += padding.encode("utf-8")
    return message


def _remove_padding(message):
    bit_cnt = message[-1]
    return message[:-bit_cnt]


def _bytes_to_bit_array(byte_string):
    bit_cnt = len(byte_string) * 8
    result = [0] * bit_cnt
    idx = 0
    for byte in byte_string:
        for bit_pos in range(7, -1, -1):
            if byte & (1 << bit_pos) > 0:
                result[idx] = 1
            idx += 1
    return result


def _bit_array_to_string(bit_array):
    result = []
    byte = 0
    for pos in range(len(bit_array)):
        byte += bit_array[pos] << (7-(pos % 8))
        if (pos % 8) == 7:
            result += [byte]
            byte = 0
    return bytes(result)


def _hex_print(block):
    s = [str(integer) for integer in block]
    b = int("".join(s), 2)
    print(hex(b)[2:].zfill(16))

#removed the if check as program wont work otherwise...
def _nsplit(data, split_size):
    # if len(data) % split_size != 0:
    #     msg = "Error: list of len {0} does not divide into {1}-sized splits".format(
    #         len(data), split_size)
    #     raise ValueError(msg)
    for n in range(0, len(data), split_size):
        yield data[n:n+split_size]


def _xor(x, y):
    return [xn ^ yn for xn, yn in zip(x, y)]


def _substitution(bit_array):
    result = []
    for i, b in enumerate(_nsplit(bit_array, 6)):
        ends = [str(b[0]), str(b[-1])]
        row = int(''.join(ends), 2)
        mids = [str(b[1]), str(b[2]), str(b[3]), str(b[4])]
        col = int(''.join(mids), 2)
        sval = sbox_tables._S_BOXES[i][row][col]
        bstr = bin(sval)[2:].zfill(4)
        result += [int(x) for x in bstr]
    return result


def _function(R, subkey):
    T = _permute(R, function_permutation_tables._EXPAND)
    T = _xor(T, subkey)
    T = _substitution(T)
    T = _permute(T, function_permutation_tables._CONTRACT)
    return T


def _encrypt_block(block, subkeys):
    block = _permute(block, function_permutation_tables._INIT_PERMUTATION)
    L = block[:32]
    R = block[32:]
    for i in range(16):
        T = _xor(L, _function(R, subkeys[i]))
        L = R
        R = T

    block = _permute(R+L, function_permutation_tables._FINAL_PERMUTATION)
    return block


def encrypt(plaintext, key):
    subkeys = _generate_subkeys(key)
    pt = _add_padding(plaintext)
    pt = _bytes_to_bit_array(pt)

    ct = []
    for block in _nsplit(pt, 64):
        ct += _encrypt_block(block, subkeys)
    ct = _bit_array_to_string(ct)
    return ct


def _permute(block, table):
    return [block[x] for x in table]


def _shift(L_values, R_values, n):
    return L_values[n:] + L_values[:n], R_values[n:] + R_values[:n]


def _generate_subkeys(key):
    subkeys = []
    keybits = _bytes_to_bit_array(key)
    k_0 = _permute(keybits, key_permutation_tables._KEY_PERMUTATION1)
    L = k_0[:28]
    R = k_0[28:]
    for i in range(16):
        L, R = _shift(L, R, key_permutation_tables._KEY_SHIFT[i])
        k_i = _permute(L + R, key_permutation_tables._KEY_PERMUTATION2)
        subkeys.append(k_i)
    return subkeys


if __name__ == "__main__":
    # Foundations Output:
    pt = b"One of the most singular characteristics of the art of deciphering is the strong conviction " +\
        b"possessed by every person, even moderately acquainted with it, that he is able to construct " +\
        b"a cipher which nobody else can decipher. I have also observed that the cleverer the person, " +\
        b"the more intimate is his conviction. -C. Babbage"
    k = b"\xEF\x00\xEF\x00\xFF\x80\xFF\x80"
    ct = encrypt(pt, k)














    print(ct)
