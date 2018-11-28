import hashlib

def checksum(x):
	s1=hashlib.sha256(bytes(bytearray.fromhex(x)))
	s2=hashlib.sha256(bytes(bytearray.fromhex(s1.hexdigest())))
	return bytes(bytearray.fromhex(s2.hexdigest()))

def p2pkh_to_address(x):
	return (b'\x00' + bytes(bytearray.fromhex(x)) + checksum('00' + x)[:4])

def p2sh_to_address(x):
	return (b'\x05' + bytes(bytearray.fromhex(x)) + checksum('05' + x)[:4])

print(p2pkh_to_address('e1d5c3b5919b5c9249469ddedd4a0ed10c5884e0').encode('hex'))


print(p2sh_to_address('2fd602e65a8da462e1871cc3a0224f730cd79269').encode('hex'))

