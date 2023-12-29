from struct import unpack, pack

class Crypt:
	def __init__(self, magic_char):
		self.title = None
		self.copyright = None
		self.project_path = None
		self.magic_char = magic_char
		self.new_game = False
		self.project_build = None
		self.valid = False
		self.game_mode = None

	def gen_key(self):
		if self.valid:
			return

		fields = [self.title, self.copyright, self.project_path]
		if self.new_game and self.project_build <= 285:
			fields = [self.project_path, self.title, self.copyright]

		keystring = []
		for f in fields:
			if f is None:
				continue
			if len(f) == 0:
				continue
			for b in f:
				if b != 0:
					keystring.append(b)

		if len(keystring) > 0x80:
			keystring = keystring[:0x80]
		lenkey = len(keystring)
		keystring += [0] * (0x100 - lenkey)
		accum = self.magic_char
		hash = self.magic_char
		for i in range(0, lenkey+1):
			hash = ((hash << 7) | (hash >> 1)) & 0xff
			keystring[i] ^= hash
			accum = (accum + (keystring[i] * ((hash & 1) + 2)) & 0xff) & 0xff
		keystring[lenkey+1] = accum
		#print("accum: %d (%02x)" % ( accum, accum & 0xff))

		self.magic_key = keystring
		self.valid = False

		decode_buffer = [0] * (64 * 16)
		for i in range (0,256):
			decode_buffer[i*4]=i

		accum = self.magic_char
		hash = self.magic_char
		never_reset_key = True

		i2 = 0
		k = 0
		for i in range(0, 0x100):
			hash = ((hash << 7) | (hash >> 1)) & 0xff
			if never_reset_key:
				accum = (accum + (keystring[k] * ((hash & 1) + 2)  & 0xff) & 0xff )
			if hash == keystring[k]:
				if never_reset_key and accum != keystring[k+1]:
					raise Exception("Failed To Generate Decode Table");

				hash = ((self.magic_char << 7) + (self.magic_char >> 1)) & 0xff
				k = 0
				never_reset_key = False

			# decode_buffer.u32[i]
			tmp = decode_buffer[4*i: 4*i+4]
			db = unpack('<L', bytes(tmp))[0]

			i2 = (i2 + (((hash ^ keystring[k]) + db) & 0xff)) & 0xff

			decode_buffer[4*i: 4*i+4] = decode_buffer[4*i2: 4*i2+4]
			decode_buffer[4*i2: 4*i2+4] = tmp

			k += 1
		self.valid = True
		self.decode_buffer = decode_buffer

	def decode(self, data, chunk_id = None):
		if not self.valid:
			self.gen_key()

		buffer = self.decode_buffer[:]

		i = 0
		i2 = 0
		out = []
		for x in data:
			if i == 0 and chunk_id is not None:
				if self.game_mode != '284' and (chunk_id & 0x1 == 0x1):
					x ^= (chunk_id ^ (chunk_id >> 8)) & 0xff

			i += 1

			tmp = buffer[4*i: 4*i+4]
			db = unpack('<L', bytes(tmp))[0]

			i2 = (i2 + db) & 0xff

			tmp2 = buffer[4*i2: 4*i2+4]
			db2 = unpack('<L', bytes(tmp2))[0]

			buffer[4*i: 4*i+4] = tmp2
			buffer[4*i2: 4*i2+4] = tmp

			out.append(x ^ buffer[4 * ((db + db2) & 0xff)])

		return bytes(out)