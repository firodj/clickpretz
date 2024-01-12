from typing import cast, BinaryIO
from struct import unpack, pack
import os, re
from . import zips
import yaml

""" wwww.Item """
class Item:
	def __init__(self, f):
		self.idx: int = None
		self.f: BinaryIO = f
		self.name_len: int = 0
		self.name: str = ''
		self.bingo: 0 = 0
		self.data_size: int = 0
		self.data_ofs: int = None
		self.compress = ''

		self.w_fdata = ''
		self.w_clevel = 0

	def get_data(self):
		f = self.f
		f.seek(self.data_ofs, os.SEEK_SET)
		data = f.read(self.data_size)

		if len(self.compress) > 0:
			data = zips.decompress(data)
		return data

	def info(self):
		print(self.idx, self.compress, self.name, self.bingo, self.data_size, hex(self.data_ofs))

	def __repr__(self):
		return 'wwww.Item(idx=%d,name="%s",compress="%s",size=%d)' % (self.idx, self.name, self.compress, self.data_size)

	def cache_file(self):
		basename, ext = os.path.splitext(self.name)
		return "out/wwww/%s;%d%s" % (basename, self.idx, ext)

	def meta(self):
		d = {
			'idx': self.idx,
			'name': self.name,
			'bingo': self.bingo,
			'compress': self.compress,
		}
		return d

""" wwww.Section """
class Section:
	def __init__(self, f: BinaryIO, start: int):
		self.f = f
		self.start = start

		self.magic: bytes = None
		self.magic2: bytes = None
		self.header_size: int = None
		self.data_size: int = None

		self.format_version: int = None
		self.count: int = None
		self.unicode = False

		self.items: list[Item] = []

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

		self.header_size = cast(list[int], unpack('<L', f.read(4)))[0]
		print("header size = %d (0x%x)" % (self.header_size, self.header_size))
		self.data_size = cast(list[int], unpack('<L', f.read(4)))[0]
		print("data size = %d (0x%x)" % (self.data_size, self.data_size))

		# Unpack First
		#f.seek(0x10, os.SEEK_SET)

		self.format_version = cast(list[int], unpack('<L', f.read(4)))[0]
		print("format version = %d (0x%x)" % (self.format_version, self.format_version))
		if self.format_version == 3:
			self.unicode = True

		f.seek(8, os.SEEK_CUR) # TODO: Skip 8 bytes

		self.count = cast(list[int], unpack('<L', f.read(4)))[0]
		print("pack count = %d" % (self.count,))

		#off = f.tell()
		#print("offset = 0x%x" % (off,))

		for idx in range(self.count):
			item = Item(f)
			item.idx = idx

			item.name_len = unpack('<H', f.read(2))[0]

			if self.unicode:
				name_wide = f.read(item.name_len *2)
				item.name = name_wide.decode('utf-16')
			else:
				item.name = f.read(item.name_len)

			item.bingo = cast(list[int], unpack('<L', f.read(4)))[0]
			item.data_size = cast(list[int], unpack('<L', f.read(4)))[0]
			item.data_ofs = f.tell()

			data = f.read(2)
			item.compress = zips.compress_level(data)

			print(item)
			self.items.append(item)

			f.seek(item.data_size - 2, os.SEEK_CUR)

	def glob(self):
		path = 'out/wwww'
		fnames = [fname for fname in os.listdir(path) if os.path.isfile(path + os.path.sep + fname)]

		refname = re.compile(r'^(.+);([^.;]+)(\.[^.]+)?$')

		items = []
		for fname in fnames:
			m = refname.match(fname)
			if not m: continue

			name = m.group(1) + m.group(3)
			item = Item(None)
			item.name = name
			item.idx = int(m.group(2))
			item.w_fdata = path + os.path.sep + fname

			with open(path + os.path.sep + fname + ".meta", 'r') as u:
				d = yaml.safe_load(u)
				if d['idx'] != item.idx:
					raise Exception("wrong meta")
				item.bingo = d['bingo']
				item.compress = d['compress']

			with open(item.w_fdata, 'rb') as f:
				data = f.read()
				item.w_clevel = 0
				match item.compress:
					case 'best':
						item.w_clevel = 9
					case 'default':
						item.w_clevel = 6
					case 'low':
						item.w_clevel = 1

				if item.w_clevel > 0:
					data = zips.compress(data, item.w_clevel)

				item.data_size = len(data)

			items.append(item)

		items.sort(key=lambda item: item.idx)
		for item in items:
			print(item)

	def testing(self, dump = False):
		for item in self.items:
			data = item.get_data()
			if dump:
				filename =item.cache_file()
				print("dump to:", filename)
				with open(filename, "wb") as u:
					u.write(data)

				filenamemeta = filename + ".meta"
				with open(filenamemeta, "w") as u:
					yaml.safe_dump(item.meta(), u)
