#!/usr/bin/env python
"""
Simple chosen-plaintext attack on AES-CTR given NONCE and IV re-use for
multiple ciphertexts

Copyleft 2011 Ian Gallagher <crash@neg9.org>
"""
import sys

def decrypt(keystream, ciphertext):
    """
    Given an ordinal list of keystream bytes, and an ordinal list of
    ciphertext, return the binary plaintext string after decryption
    (standard XOR - applicable for AES-CTR mode, etc.)
    """
    pt = ''
    for pos in xrange(len(ciphertext)):
        if pos >= len(keystream):
            print >>sys.stderr, "Ran out of keystream material at pos = %d" % pos
            break
        else:
            pt += chr(ciphertext[pos] ^ keystream[pos])
    return(pt)

def derivekeystream(chosen_ciphertext, chosen_plaintext):
    """
    Given an ordinal list of a chosen plaintext and the corrosponding chosen
    ciphertext, derive AES-CTR keystream and return it as an ordinal list
    """
    return map(lambda x: x[0] ^ x[1], zip(map(ord, chosen_ciphertext), map(ord, chosen_plaintext)))

def main():
    """
    chosen_ciphertext and target_ciphertext should be in the binary encrypted
    format, so prepare it by base64 decoding it, or whatever.

    chosen_plaintext should be in the resulting binary/ASCII format of the
    origial data.
    """
    chosen_plaintext = 'https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation'
    chosen_ciphertext = '070d05e12e6001c95c8524664ec16ca5a8a0f1569cdba7ca408326cb309daf3f38c0094167a792030a95feeacaa515365a58b91fa0716fdda044a42a'.decode('hex')

    keystream = derivekeystream(chosen_ciphertext, chosen_plaintext)
    target_ciphertext = '18181fff3c3d4f8b5c903a2141cb35e2fda6ae0787d6e5c857952ec16a8389323293542d33f9d5595bd399b5c4a21350075a9b'.decode('hex')

    print decrypt(keystream, map(ord, target_ciphertext))

if '__main__' == __name__:
	main()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4