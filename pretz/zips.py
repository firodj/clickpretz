import zlib

""" https://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations """
def decompress(data):
	zdec = zlib.decompressobj(0)
	inflated = zdec.decompress(data)
	inflated += zdec.flush()
	return inflated

def compress(data, compresslevel=9):
    zcomp = zlib.compressobj(
            compresslevel,        # level: 0-9
            zlib.DEFLATED,        # method: must be DEFLATED
            zlib.MAX_WBITS,      # window size in bits:
                                  #   -15..-9: negate, suppress header
                                  #    +9..+15: normal
                                  #   +25..+31: subtract 16, gzip header
            zlib.DEF_MEM_LEVEL,   # mem level: 1..8/9
            0                     # strategy:
                                  #   0 = Z_DEFAULT_STRATEGY
                                  #   1 = Z_FILTERED
                                  #   2 = Z_HUFFMAN_ONLY
                                  #   3 = Z_RLE
                                  #   4 = Z_FIXED
    )
    deflated = zcomp.compress(data)
    deflated += zcomp.flush()
    return deflated

def mode_description(mode):
	return {
		0: "Uncompressed / Unencrypted",
		1: "Compressed / Unencrypted",
		2: "Uncompressed / Encrypted",
		3: "Compressed / Encrypted",
		4: "LZ4 Compressed"
	}[mode]

def compress_level(data):
	if data[:2] == b'\x78\xda': # 9
		return 'best'
	elif data[:2] == b'\x78\x9c': #6
		return 'default'
	elif data[:2] == b'\x78\x01': #1
		return 'low'
	return ''
