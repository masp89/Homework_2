# Homework 2 for cryptography course
# By Maria

import sys
from Crypto.Cipher import AES
import numpy


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


def main(k_raw):
    check_len(k_raw, c_raw)
    raw2list(k_raw)

print('Jämför storlek på nycklar och ciphertext')

def check_len(str1, str2):
    if len(str1) == len(str2):
            print('Storlek på vektorer OK!')
            return
    else:
            print('Fel storlek på nyckelvektor eller ciphertextvektor!')
            return

def raw2list(raw):
    final_list=[]
    until_list = list(range(len(raw)))
    for i in until_list:
        temp_list = raw[i]
        final_list.append(until_list)

    #for i in until_list:
	#templist = list(raw[i])
	#for j in raw[i]:
	#    list.append(j)
	#print(list[i])







# Definiera objektet cipher
# cipher = AES.new(k[1], AES.MODE_ECB)

main(k_raw)