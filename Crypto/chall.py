import os
from Crypto.Cipher import AES
from Crypto.Util import Counter

key = os.urandom(16)
iv = os.urandom(16)

def encrypt(key, iv, plaintext):
	ctr = Counter.new(128, initial_value = int(iv.encode("hex"), 16))
	aes = AES.new(key, AES.MODE_CTR, counter = ctr)
	ciphertext = aes.encrypt(plaintext)
	return ciphertext

hint = open("hint.txt", "r").read()
flag = open("flag.txt", "r").read()

print "i will give you a hint:", hint
# i will give you a hint: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

print encrypt(key, iv, hint).encode("hex")
# 070d05e12e6001c95c8524664ec16ca5a8a0f1569cdba7ca408326cb309daf3f38c0094167a792030a95feeacaa515365a58b91fa0716fdda044a42a
print encrypt(key, iv, flag).encode("hex")
# 18181fff3c3d4f8b5c903a2141cb35e2fda6ae0787d6e5c857952ec16a8389323293542d33f9d5595bd399b5c4a21350075a9b
