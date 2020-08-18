bytes_list = [53, 13, 56, 56, 8, 116, 93, 43, 11, 43, 0, 5, 24, 116, 12, 21, 17, 110, 29, 119, 50, 49, 111, 43, 59, 6, 23, 58]
key = 'SaY_s0mE_tH1nG'
flag = ''

for i in range(len(bytes_list)):
	flag += chr(bytes_list[i] ^ ord(key[i % len(key)]))

print "Flag: %s" % flag