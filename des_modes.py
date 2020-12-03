import des_core as core
import sys


def encrypt(plaintext, key, mode="ECB", iv=None):
    subkeys = core._generate_subkeys(key)

    if mode == "CBC" or mode == "OFB":
        iv = core._bytes_to_bit_array(iv)

    # if mode == "ECB" or mode == "CBC":
    #     plaintext = core._add_padding(plaintext)
    pt = core._bytes_to_bit_array(plaintext)

    ct = []
    for pt_block in core._nsplit(pt, 64):
        if mode == "ECB":
            ct_block = core._encrypt_block(pt_block, subkeys)
            ct += ct_block

        elif mode == "CBC":
            ct_block = core._xor(pt_block, iv)
            ct_block = core._encrypt_block(ct_block, subkeys)
            iv = ct_block
            ct += ct_block

        elif mode == "OFB":
            iv = core._encrypt_block(iv, subkeys)
            ct_block = core._xor(pt_block, iv)
            ct += ct_block
        else:
            raise ValueError("Mode '{} is not a valid mode".format(mode))
    ct = core._bit_array_to_string(ct)
    return ct


def decrypt(ciphertext, key, mode="ECB", iv=None):
    subkeys = core._generate_subkeys(key)

    if mode != "OFB":
        subkeys = list(reversed(subkeys))
    if mode == "CBC" or mode == "OFB":
        iv = core._bytes_to_bit_array(iv)

    ct = core._bytes_to_bit_array(ciphertext)

    pt = []
    for ct_block in core._nsplit(ct, 64):
        if mode == "ECB":
            pt += core._encrypt_block(ct_block, subkeys)
        elif mode == "CBC":
            pt_block = core._encrypt_block(ct_block, subkeys)
            pt_block = core._xor(pt_block, iv)
            iv = ct_block
            pt += pt_block
        elif mode == "OFB":
            iv = core._encrypt_block(iv, subkeys)
            pt_block = core._xor(iv, ct_block)
            pt += pt_block
        else:
            raise ValueError("Mode '{}' is not a valid mode".format(mode))

    pt = core._bit_array_to_string(pt)
    if mode == "ECB" or mode == "CBC":
        pt = core._remove_padding(pt)
    return pt


if __name__ == "__main__":
    pt = b"One of the most singular characteristics of the art of deciphering is the strong conviction " +\
        b"possessed by every person, even moderately acquainted with it, that he is able to construct " +\
        b"a cipher which nobody else can decipher. I have also observed that the cleverer the person, " +\
        b"the more intimate is his conviction. -C. Babbage"
    k = b"\xef\x00\xef\x00\xff\x80\xff\x80"
    iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    ct = encrypt(pt, k, "CBC", iv)
    print(ct.hex())
    pt = decrypt(ct, k, "CBC", iv)
    print(pt)
