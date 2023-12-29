from typing import BinaryIO, cast
import os
from . import zips, defs, crypts, strs, imgs
from struct import unpack, pack
from io import BytesIO

class Item:
	def __init__(self, pam_section, f: BinaryIO):
		self.pam_section: Section = pam_section
		self.idx = -1
		self.f = f
		self.chunk_id = None
		self.mode = 0
		self.chunk_size = None
		self.chunk_ofs = None

		self.data_ofs = None
		self.data_size = None
		self.encrypted_size: int = None
		self.expected_size: int = None
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
				data = zips.decompress(rawdata)
			case 2:
				f.seek(self.data_ofs, os.SEEK_SET)
				data = f.read(self.chunk_size)
				data = self.pam_section.decryptor.decode(data, self.chunk_id)
				#print(bytes(out).hex(':'))
			case 3:
				f.seek(self.data_ofs, os.SEEK_SET)
				data = f.read(self.data_size)
				data = self.pam_section.decryptor.decode(data, self.chunk_id)
				data = zips.decompress(data[4:])
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
		print("---\n%d. chunk id = 0x%x (%s)" % (self.idx, self.chunk_id, defs.chunk_type(self.chunk_id)))
		print("mode = %d (%s)" % (self.mode, zips.mode_description(self.mode)))
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
		return 'Item(idx=%d,type=%s,chunk_id=0x%04x,mode=%d,size=%d)' % (self.idx, defs.chunk_type(self.chunk_id),
														self.chunk_id, self.mode, self.chunk_size)

	def cache_file(self):
		name = "%s_%03d.bin" % (defs.chunk_type(self.chunk_id), self.idx)
		return open('out/chunks/' + name, "rb")

	def cache_dump(self):
		name = "%s_%03d.bin" % (defs.chunk_type(self.chunk_id), self.idx)
		print("dump to out/chunks/%s"  %  (name))
		with open('out/chunks/' + name, "wb") as u:
			u.write(self.get_data())

class Section:
	def __init__(self, f, start):
		self.f: BinaryIO = f
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
		self.items: list[Item] = []
		self.ccn_game = None

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

		self.runtime_sub_version = unpack('<H', f.read(2))[0]
		print("runtime sub version = %d (0x%x)" % (self.runtime_sub_version, self.runtime_sub_version))

		self.runtime_version = unpack('<H', f.read(2))[0]
		print("runtime version = %d (0x%x)" % (self.runtime_version, self.runtime_version))

		self.product_version = unpack('<L', f.read(4))[0]
		print("product version = %d (0x%x)" % (self.product_version, self.product_version))

		self.product_build = unpack('<L', f.read(4))[0]
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

		self.decryptor = crypts.Crypt(magic_char)
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
		item = Item(self, f)
		start = f.tell()

		bindata = f.read(2)
		if len(bindata) < 2:
			if start != f.tell():
				print("warning: leftover")
			else:
				print("congratlation: complete processed")
			return None

		item.chunk_id = unpack('<H', bindata)[0]
		item.mode = unpack('<H', f.read(2))[0]
		item.chunk_size = unpack('<L', f.read(4))[0]
		item.chunk_ofs = f.tell()
		chunk_data_end = item.chunk_ofs + item.chunk_size

		data = None
		match item.mode:
			case 1:
				item.expected_size = unpack('<L', f.read(4))[0]

				item.data_size = 0
				if not self.new_game:
					if item.chunk_size > 4:
						item.data_size = item.chunk_size - 4
				else:
					item.data_size = unpack('<L', f.read(4))[0]

				item.data_ofs = f.tell()

				data = f.read(2)
				item.compress =  zips.compress_level(data)
			case 2:
				item.data_ofs = f.tell()

			case 3:
				item.encrypted_size = unpack('<L', f.read(4))[0]

				item.data_size = 0
				if item.chunk_size > 4:
					item.data_size = item.chunk_size - 4

				item.data_ofs = f.tell()

				data = f.read(8)
				data = self.decryptor.decode(data, item.chunk_id)

				item.expected_size = unpack('<L', data[0:4])[0]

				item.compress =  zips.compress_level(data[4:])
			case 4:
				raise Exception("not yet implemented for lz4")
			case _:
				item.data_ofs = f.tell()

		match defs.chunk_type(item.chunk_id):
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
		if type(data) is bytes:
			data = BytesIO(data)
		return strs.String(data, self.unicode)

	def get_item(self, idx: int):
		item = self.items[idx]
		data = None
		try:
			data = item.cache_file() #get_data()
		finally:
			data = BytesIO(item.get_data())

		match defs.chunk_type(item.chunk_id):
			case 'title':
				return self.to_string(data)
			case 'title2':
				return data
			case 'output_path':
				return self.to_string(data)
			case 'project_path':
				return self.to_string(data)
			case 'author':
				return self.to_string(data)
			case 'about':
				return self.to_string(data)
			case 'copyright':
				return self.to_string(data)
			case 'image_bank':
				return imgs.ImageBank(data, self.product_build, self.new_game, self.ccn_game)

	def testing(self, dump=False):
		for item in self.items:
			data = item.get_data()

			match defs.chunk_type(item.chunk_id):
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
					data_begin = unpack('<L', data[0:4])[0]

					with open('out/icon.ico', "wb") as u:
						u.write(data)
				case 'last':
					pass
				case None:
					raise Exception("unknown chunk_id = %04x" % (self.chunk_id,))

			if dump:
				item.cache_dump()
