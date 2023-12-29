import zlib

""" https://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations """
def decompress(data):
	zdec = zlib.decompressobj(0)
	inflated = zdec.decompress(data)
	inflated += zdec.flush()
	return inflated

def mode_description(mode):
	return {
		0: "Uncompressed / Unencrypted",
		1: "Compressed / Unencrypted",
		2: "Uncompressed / Encrypted",
		3: "Compressed / Encrypted",
		4: "LZ4 Compressed"
	}[mode]

def compress_level(data):
	if data[:2] == b'\x78\xda':
		return 'best'
	elif data[:2] == b'\x78\x9c':
		return 'default'
	elif data[:2] == b'\x78\x01':
		return 'low'
	return ''
