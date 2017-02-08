# Homework 2 for cryptography course
# By Maria

import sys
from Crypto.Cipher import AES
import binascii


# Definiera, crypteringsläge, nycklar (128 bit) och ciphertexter.
mode = ['CBC',
    	'CBC',
	    'CTR',
	    'CTR']

k_raw = ['140b41b22a29beb4061bda66b6747e14',
    	'140b41b22a29beb4061bda66b6747e14',
    	'36f18357be4dbd77f050515c73fcf9f2',
    	'36f18357be4dbd77f050515c73fcf9f2']

c_raw = ['4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81',
    	'5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253',
    	'69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329',
    	'770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451']

# Huvudfunktion
def main(k_raw):
    # Kontrollera att det finns lika många nycklar som ciphertexter.
    check_len(k_raw, c_raw)
    # Dela upp hex-strängen i block om 32 hex-tecken.
    k_blocks = raw2blocks(k_raw)
    c_blocks = raw2blocks(c_raw)
    # Ta ut initieringsvektorn från varje ciphertext.
    i_vec = ivec(c_blocks)

    output = cbc_full(i_vec[0], k_blocks[0], c_blocks[0])





#####################################################################
######################### Hjälpfunktioner ###########################
#####################################################################


def cbc_full(iv_hex, key_hex, c_text_hex):
    iv = iv_hex
    out = []
    for i in list(range(len(c_text_hex))):
        temp_plain = cbc_dec(iv, key_hex[0], c_text_hex[i])
        iv = temp_plain
        out.append(temp_plain)

def cbc_dec(iv_hex, key_hex, c_text_hex):
    print(iv_hex)
    print(key_hex)
    print(c_text_hex)

    iv = binascii.unhexlify(iv_hex)



    #key_str = "".join(key_hex)
    #c_text_str = "".join(c_text_hex)
    #iv_str = "".join(iv_hex)
    #out = decrypt(key_bin, c_text_bin) ^ iv_bin
    #return(out)






def ivec(raw):
    i_vec = []
    for x in list(range(len(raw))):
        c_list = (raw[x])
        i_vec.append(c_list[0])
    return(i_vec)



# Funktion för att kontrollera att det finns lika många nycklar som ciphertexter.
def check_len(str1, str2):
    print('Jämför storlek på nycklar och ciphertext')
    if len(str1) == len(str2):
            print('Storlek på vektorer OK!')
            return
    else:
            print('Fel storlek på nyckelvektor eller ciphertextvektor!')
            return

# Funktion för att göra om strängar till listor med en bokstav i varje plats.
def raw2list(raw):
    final_list=[]
    until_list_i = list(range(len(raw)))
    for i in until_list_i:
        row_i = raw[i]
        until_list_j = list(range(len(row_i)))
        temp_chars_j = []
        for j in until_list_j:
            temp_chars_j.append(row_i[j])
        final_list.append(temp_chars_j)
    return(final_list)

# Funktion för att dela upp de råa strängarna i block
def raw2blocks(raw):
    block_length = 32 # 128 bitar blir 32 hex-värden.
    list_out = []
    separated_lists = raw2list(raw)
    until_list_i = list(range(len(raw)))
    for i in until_list_i:
        row_i = raw[i]
        list_len = (len(row_i)//block_length)
        if len(row_i)%block_length != 0:
            list_len += 1
        until_list_j = [x for x in list(range(list_len))]
        temp_block = []
        for j in until_list_j:
            temp_block.append(row_i[j:j+block_length])
        list_out.append(temp_block)
    return(list_out)

def decrypt(key, c_text):
    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.decrypt(c_text)
    return(output)

main(k_raw)