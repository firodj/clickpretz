import os, sys, struct
import pefile
import zlib
import typing
from typing import cast

""" https://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations """
def decompress(data):
	zdec = zlib.decompressobj(0)
	inflated = zdec.decompress(data)
	inflated += zdec.flush()
	return inflated

def chunk_type(chunk_id):
	return {
		0x0302: 'entry',
		0x1122: 'vitalise_preview',
		0x2223: 'header',
		0x2224: 'title',
		0x2225: 'author',
		0x2226: 'menu',
		0x2227: 'extra_path',
		0x2228: 'extensions',
		0x2229: 'object_bank', # frameitems
		0x222A: 'global_events',
		0x222B: 'frame_handles',
		0x222C: 'extra_data',
		0x222D: 'additional_extensions',
		0x222E: 'project_path',
		0x222F: 'output_path',
		0x2230: 'app_doc',
		0x2231: 'other_extension',
		0x2232: 'global_values',
		0x2233: 'global_strings',
		0x2234: 'extensions_list',
		0x2235: 'icon',
		0x2236: 'demo_version',
		0x2237: 'security_number',
		0x2238: 'binary_files',
		0x2239: 'menu_images',
		0x223A: 'about',
		0x223B: 'copyright',
		0x223C: 'global_value_names',
		0x223D: 'global_string_names',
		0x223E: 'movement_extensions',
		0x223F: 'unknown8',
		0x223F: 'object_bank2', # frameitems2
		0x2240: 'exe_only',
		#0x2241
		0x2242: 'protection',
		0x2243: 'shaders',
		#0x2244
		0x2245: 'extended_header',
		0x2246: 'spacer',
		0x224D: 'frame_bank', # FRAMEHANDLES might be broken
		0x224F: 'chunk224F',
		0x2251: 'title2',
		0x2253: 'chunk2253',
		0x2254: 'object_names',
		0x2255: 'chunk2255',
		0x2256: 'two_five_plus_object_properties',
		0x2257: 'chunk2257',
		0x2258: 'font_meta',
		0x2259: 'font_chunk',
		0x225A: 'shaders2',
		0x3333: 'frame',
		0x3334: 'frame_header',
		0x3335: 'frame_name',
		0x3336: 'frame_password',
		0x3337: 'frame_palette',
		0x3338: 'frame_object_instances',
		0x3339: 'frame_fade_in_frame',
		0x333A: 'frame_fade_out_frame',
		0x333B: 'frame_fade_in',
		0x333C: 'frame_fade_out',
		0x333D: 'frame_events',
		0x333E: 'frame_play_header',
		0x333F: 'frame_additional_items',
		0x3340: 'frame_additional_items_instances',
		0x3341: 'frame_layers',
		0x3342: 'frame_virtual_size',
		0x3343: 'demo_file_path',
		0x3344: 'random_seed',
		0x3345: 'frame_layer_effect',
		0x3346: 'frame_bluray',
		0x3347: 'movement_timer_base',
		0x3348: 'mosaic_image_table',
		0x3349: 'frame_effects',
		0x334A: 'frame_iphone_options',
		0x334C: 'frame_chunk334C',
		0x4150: 'pa_error',
		0x4444: 'object_header',
		0x4445: 'object_name',
		0x4446: 'object_properties',
		0x4447: 'object_chunk4447',
		0x4448: 'object_effect',
		0x5555: 'image_handles',
		0x5556: 'font_handles',
		0x5557: 'sound_handles',
		0x5558: 'music_handles',
		0x6665: 'bank_offsets',
		0x6666: 'image_bank',
		0x6667: 'font_bank',
		0x6668: 'sound_bank',
		0x6669: 'music_bank',
		0x7EEE: 'fusion_3_seed',
		0x7F7F: 'last',
	}[chunk_id]

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

class PretzString:
	def __init__(self, data, is_unicode):
		self.data = data
		self.encoding = 'utf-8'
		if is_unicode:
			self.encoding = 'utf-16'
	def __str__(self):
		return self.data.decode(self.encoding)

class PretzCrypt:
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
			if len(f.data) == 0:
				continue
			for b in f.data:
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
			db = struct.unpack('<L', bytes(tmp))[0]

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
			db = struct.unpack('<L', bytes(tmp))[0]

			i2 = (i2 + db) & 0xff

			tmp2 = buffer[4*i2: 4*i2+4]
			db2 = struct.unpack('<L', bytes(tmp2))[0]

			buffer[4*i: 4*i+4] = tmp2
			buffer[4*i2: 4*i2+4] = tmp

			out.append(x ^ buffer[4 * ((db + db2) & 0xff)])

		return bytes(out)

class PretzWWWWItem:
	def __init__(self, f):
		self.idx: int = None
		self.f: typing.BinaryIO = f
		self.name_len: int = 0
		self.name: str = ''
		self.bingo: 0 = 0
		self.data_size: int = 0
		self.data_ofs: int = None
		self.compress = ''

	def get_data(self):
		f = self.f
		f.seek(self.data_ofs, os.SEEK_SET)
		data = f.read(self.data_size)

		if len(self.compress) > 0:
			data = decompress(data)
		return data

	def info(self):
		print(self.idx, self.compress, self.name, self.bingo, self.data_size, hex(self.data_ofs))

	def __repr__(self):
		return 'PretzWWWWItem(idx=%d,name="%s",compress="%s",size=%d)' % (self.idx, self.name, self.compress, self.data_size)

class PretzWWWW:
	def __init__(self, f, start):
		self.f: typing.BinaryIO = f
		self.start = start

		self.magic: bytes = None
		self.magic2: bytes = None
		self.header_size: int = None
		self.data_size: int = None

		self.format_version: int = None
		self.count: int = None
		self.unicode = False

		self.items = []

	def check_unicode(self):
		# maybe using self.format_version == 3 is enough
		# but this is another way of, from lak
		f = self.f
		entry_start_ofs = self.start + self.data_size - self.header_size
		f.seek(entry_start_ofs, os.SEEK_SET)

		pam_header = f.read(4)
		if pam_header == b'PAMU':
			self.unicode = True

	def parse(self):
		f = self.f
		f.seek(self.start)

		self.magic = f.read(4)
		if self.magic != b'wwww':
			raise Exception("expecring magic = wwww, not = %s" % (self.magic,))

		self.magic2 = f.read(4)

		self.header_size = cast(list[int], struct.unpack('<L', f.read(4)))[0]
		print("header size = %d (0x%x)" % (self.header_size, self.header_size))
		self.data_size = cast(list[int], struct.unpack('<L', f.read(4)))[0]
		print("data size = %d (0x%x)" % (self.data_size, self.data_size))

		# Unpack First
		#f.seek(0x10, os.SEEK_SET)

		self.format_version = cast(list[int], struct.unpack('<L', f.read(4)))[0]
		print("format version = %d (0x%x)" % (self.format_version, self.format_version))
		if self.format_version == 3:
			self.unicode = True

		f.seek(8, os.SEEK_CUR) # TODO: Skip 8 bytes

		self.count = cast(list[int], struct.unpack('<L', f.read(4)))[0]
		print("pack count = %d" % (self.count,))

		#off = f.tell()
		#print("offset = 0x%x" % (off,))

		for idx in range(self.count):
			item = PretzWWWWItem(f)
			item.idx = idx

			item.name_len = struct.unpack('<H', f.read(2))[0]

			if self.unicode:
				name_wide = f.read(item.name_len *2)
				item.name = name_wide.decode('utf-16')
			else:
				item.name = f.read(item.name_len)

			item.bingo = cast(list[int], struct.unpack('<L', f.read(4)))[0]
			item.data_size = cast(list[int], struct.unpack('<L', f.read(4)))[0]
			item.data_ofs = f.tell()

			data = f.read(2)
			item.compress = compress_level(data)

			print(item)
			self.items.append(item)

			f.seek(item.data_size - 2, os.SEEK_CUR)

	def testing(self, dump = False):
		for item in self.items:
			data = item.get_data()
			if dump:
				print("dump to out/%s"  %  (item.name,))
				with open('out/' + item.name, "wb") as u:
					u.write(data)

class PretzPamItem:
	def __init__(self, pam_section, f):
		self.pam_section: PretzPam = pam_section
		self.idx = None
		self.f: typing.BinaryIO = f
		self.chunk_id = None
		self.mode = None
		self.chunk_size = None
		self.chunk_ofs = None

		self.data_ofs = None
		self.data_size = None
		self.encrypted_size = None
		self.expected_size = None
		self.compress = ''

	def get_data(self):
		f = self.f
		f.seek(self.chunk_ofs, os.SEEK_SET)

		chunk_data_end = self.chunk_ofs + self.chunk_size

		data = None
		match self.mode:
			case 1:
				f.seek(self.data_ofs, os.SEEK_SET)
				rawdata = f.read(self.data_size)
				data = decompress(rawdata)
			case 2:
				f.seek(self.data_ofs, os.SEEK_SET)
				data = f.read(self.chunk_size)
				data = self.pam_section.decryptor.decode(data, self.chunk_id)
				#print(bytes(out).hex(':'))
			case 3:
				f.seek(self.data_ofs, os.SEEK_SET)
				data = f.read(self.data_size)
				data = self.pam_section.decryptor.decode(data, self.chunk_id)
				data = decompress(data[4:])
				try:
					print(data.decode('utf-8'))
				except:
					print(data.hex(':'))
			case 4:
				raise Exception("not yet implemented for lz4")
			case _:
				f.seek(self.data_ofs, os.SEEK_SET)
				data = f.read(self.chunk_size)

		if f.tell() != chunk_data_end:
			raise Exception("unexpected different position")

		return data

	def info(self):
		print("---\n%d. chunk id = 0x%x (%s)" % (self.idx, self.chunk_id, chunk_type(self.chunk_id)))
		print("mode = %d (%s)" % (self.mode, mode_description(self.mode)))
		print("chunk size = %d (0x%x)" % (self.chunk_size, self.chunk_size))
		print("chunk ofs = %d (0x%x)" % (self.chunk_ofs, self.chunk_ofs))
		print("data ofs = %d (0x%x)" % (self.data_ofs, self.data_ofs))
		if self.encrypted_size:
			print("encrypted size = %d (0x%x)" % (self.encrypted_size, self.encrypted_size))
		if self.expected_size:
			print("expected size = %d (0x%x)" % (self.expected_size, self.expected_size))
		if self.data_size:
			print("data size = %d (0x%x)" % (self.data_size, self.data_size))

		print("compress = %s" % (self.compress,))

	def __repr__(self):
		return 'PretzPamItem(idx=%d,type="%s")' % (self.idx, chunk_type(self.chunk_id))

class PretzPam:
	def __init__(self, f, start):
		self.f: typing.BinaryIO = f
		self.start = start
		self.unicode = False
		self.magic = None
		self.runtime_sub_version = None
		self.runtime_version = None
		self.product_version = None
		self.product_build = None
		self.new_game = None
		self.game_mode = None
		self.entry_ofs = None
		self.decryptor = None
		self.items: list[PretzPamItem] = []

	def parse(self):
		f = self.f
		f.seek(self.start, os.SEEK_SET)

		self.magic = f.read(4)
		print("magic = ", self.magic)

		if self.magic == b'PAMU':
			self.unicode = True
		elif self.magic == b'PAME':
			pass
		else:
			raise Exception("unexpected pam header %s" % (self.magic,))

		print("unicode game = %s" %(self.unicode,))

		self.runtime_sub_version = struct.unpack('<H', f.read(2))[0]
		print("runtime sub version = %d (0x%x)" % (self.runtime_sub_version, self.runtime_sub_version))

		self.runtime_version = struct.unpack('<H', f.read(2))[0]
		print("runtime version = %d (0x%x)" % (self.runtime_version, self.runtime_version))

		self.product_version = struct.unpack('<L', f.read(4))[0]
		print("product version = %d (0x%x)" % (self.product_version, self.product_version))

		self.product_build = struct.unpack('<L', f.read(4))[0]
		print("product build = %d (0x%x)" % (self.product_build, self.product_build))

		#entry_ofs = f.tell()

		self.game_mode = "284"
		self.new_game = False
		magic_char = 54 # 'c'

		if self.product_build < 284:
			self.game_mode = "OLD"
			magic_char = 99 # '6'
		elif self.product_build > 285:
			self.game_mode = "288"
			self.new_game =  True

		self.decryptor = PretzCrypt(magic_char)
		self.decryptor.project_build = self.product_build
		self.decryptor.new_game = self.new_game
		self.decryptor.game_mode = self.game_mode

		#f.seek(entry_ofs, os.SEEK_SET)
		i = 0
		while True:
			item = self.analyze_chunks(f)
			if item is None:
				break
			item.idx = i
			self.items.append(item)
			print(item)
			i += 1

	def analyze_chunks(self, f):
		item = PretzPamItem(self, f)
		start = f.tell()

		bindata = f.read(2)
		if len(bindata) < 2:
			if start != f.tell():
				print("warning: leftover")
			else:
				print("congratlation: complete processed")
			return None

		item.chunk_id = struct.unpack('<H', bindata)[0]
		item.mode = struct.unpack('<H', f.read(2))[0]
		item.chunk_size = struct.unpack('<L', f.read(4))[0]
		item.chunk_ofs = f.tell()
		chunk_data_end = item.chunk_ofs + item.chunk_size

		data = None
		match item.mode:
			case 1:
				item.expected_size = struct.unpack('<L', f.read(4))[0]

				item.data_size = 0
				if not self.new_game:
					if item.chunk_size > 4:
						item.data_size = item.chunk_size - 4
				else:
					item.data_size = struct.unpack('<L', f.read(4))[0]

				item.data_ofs = f.tell()

				data = f.read(2)
				item.compress =  compress_level(data)
			case 2:
				item.data_ofs = f.tell()

			case 3:
				item.encrypted_size = struct.unpack('<L', f.read(4))[0]

				item.data_size = 0
				if item.chunk_size > 4:
					item.data_size = item.chunk_size - 4

				item.data_ofs = f.tell()

				data = f.read(8)
				data = self.decryptor.decode(data, item.chunk_id)

				item.expected_size = struct.unpack('<L', data[0:4])[0]

				item.compress =  compress_level(data[4:])
			case 4:
				raise Exception("not yet implemented for lz4")
			case _:
				item.data_ofs = f.tell()

		match chunk_type(item.chunk_id):
			case 'title':
				data  = item.get_data()
				value = self.to_string(data)
				self.decryptor.title = value
				print("title = %s" % (value,))
				print("data =",  data.hex(':'))

			case 'project_path':
				data  = item.get_data()
				value = self.to_string(data)
				self.decryptor.project_path = value
				print("project_path = %s" % (value,))
				print("data =",  data.hex(':'))

			case 'copyright':
				data  = item.get_data()
				value = self.to_string(data)
				self.decryptor.copyright = value
				print("copyright = %s" % (value,))
				print("data =",  data.hex(':'))

			case None:
				raise Exception("unknown chunk_id = %04x" % (self.chunk_id,))

		f.seek(chunk_data_end, os.SEEK_SET)
		return item

	def to_string(self, data):
		return PretzString(data, self.unicode)

	def testing(self, dump=False):
		for item in self.items:
			data = item.get_data()

			match chunk_type(item.chunk_id):
				case 'title':
					value = self.to_string(data)
					print("title = %s" % (value,))
				case 'title2':
					print("title2 = %s" % (data,))
				case 'output_path':
					value = self.to_string(data)
					print("output_path = %s" % (value,))
				case 'project_path':
					value = self.to_string(data)
					print("project_path = %s" % (value,))
				case 'author':
					value = self.to_string(data)
					print("author = %s" % (value,))
				case 'about':
					value = self.to_string(data)
					print("about = %s" % (value,))
				case 'copyright':
					value = self.to_string(data)
					print("copyright = %s" % (value,))
				case 'icon':
					data_begin = struct.unpack('<L', data[0:4])[0]

					with open('out/icon.ico', "wb") as u:
						u.write(data)
				case 'last':
					pass
				case None:
					raise Exception("unknown chunk_id = %04x" % (self.chunk_id,))

			if dump:
				name = "%s_%03d.bin" % (chunk_type(item.chunk_id), item.idx)
				print("dump to out/chunks/%s"  %  (name))
				with open('out/chunks/' + name, "wb") as u:
					u.write(data)

class ClickPretz:
	def __init__(self, filename):
		self.filename = filename
		self.wwww_section = None

	def dump(self):
		print("analyzing pe %s" % (self.filename,))
		pe = pefile.PE(self.filename)
		start = pe.get_overlay_data_start_offset()
		print("overlay data 0x%x" % (start,))
		with open(self.filename, "rb") as s:
			s.seek(start, os.SEEK_SET)
			r = s.read()
			with open(self.filename + ".app", "wb") as t:
				t.write(r)

	def analyze(self):
		if not os.path.exists(self.filename + ".app"):
			self.dump()
		self.filehandle = open(self.filename + ".app", "rb")
		f = self.filehandle

		pos = f.tell()

		magic = f.read(4)
		if magic != b'wwww':
			raise Exception("unknown magic", magic)

		self.wwww_section = PretzWWWW(f, pos)
		self.new_game = True
		self.wwww_section.parse()

		entry_start_ofs = self.wwww_section.data_size - self.wwww_section.header_size
		if f.tell() != entry_start_ofs:
			print("warning: entry_start_ofs different")

		self.pam_section = PretzPam(f, entry_start_ofs)
		self.pam_section.parse()

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print("missing argument")
		sys.exit(1)

	filename = sys.argv[1]
	clickPretz = ClickPretz(filename)
	clickPretz.analyze()
	#click_Pretz.wwww_section.testing(False)
	clickPretz.pam_section.testing(True)
