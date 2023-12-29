import os, sys, struct
import pefile

import typing
from typing import cast, Final
from io import BytesIO
from enum import Enum, IntFlag
from PIL import Image
import numpy as np

from pretz import defs, zips, strs, crypts, wwww

class PretzPamItem:
	def __init__(self, pam_section, f):
		self.pam_section: PretzPam = pam_section
		self.idx = -1
		self.f: typing.BinaryIO = f
		self.chunk_id = None
		self.mode = 0
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
		return 'PretzPamItem(idx=%d,type=%s,chunk_id=0x%04x,mode=%d,size=%d)' % (self.idx, defs.chunk_type(self.chunk_id),
														self.chunk_id, self.mode, self.chunk_size)

	def cache_file(self):
		name = "%s_%03d.bin" % (defs.chunk_type(self.chunk_id), self.idx)
		return open('out/chunks/' + name, "rb")

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
				item.compress =  zips.compress_level(data)
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
		return strs.String(data, self.unicode)

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
					data_begin = struct.unpack('<L', data[0:4])[0]

					with open('out/icon.ico', "wb") as u:
						u.write(data)
				case 'last':
					pass
				case None:
					raise Exception("unknown chunk_id = %04x" % (self.chunk_id,))

			if dump:
				name = "%s_%03d.bin" % (defs.chunk_type(item.chunk_id), item.idx)
				print("dump to out/chunks/%s"  %  (name))
				with open('out/chunks/' + name, "wb") as u:
					u.write(data)

	def testing_images(self, select_number):
		with self.items[77].cache_file() as f:
			imageBank = ImageBank(f)
			imageBank.parse()

			select_numbers = list([select_number])
			show_image = None
			if select_number == -1:
				select_numbers = range(0, len(imageBank.items))

			print('select_number =', select_number)
			for select_number in select_numbers:
				item = imageBank.items[select_number]

				print("create image... idx =", item.idx)
				pixels = item.get_pixels()
				img = Image.fromarray(pixels, 'RGBA')

				if len(select_numbers) == 1:
					show_image = img
				elif item.experiment_show:
					if item.idx <= 100: continue
					show_image = img
					break

			if show_image: show_image.show()

class ClickPretz:
	def __init__(self, filename):
		self.filename = filename
		self.ccn_game = None
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
		self.ccn_game = False
		if magic != b'wwww':
			self.ccn_game = True
			raise Exception("unknown magic", magic)

		self.wwww_section = wwww.Section(f, pos)
		self.new_game = True
		self.wwww_section.parse()

		entry_start_ofs = self.wwww_section.data_size - self.wwww_section.header_size
		if f.tell() != entry_start_ofs:
			print("warning: entry_start_ofs different")

		self.pam_section = PretzPam(f, entry_start_ofs)
		self.pam_section.parse()

def ColorFrom32bitRGBA(d: typing.BinaryIO):
	return struct.unpack('<BBBB', d.read(4))

class PretzImageItem:
	def  __init__(self, f: typing.BinaryIO):
		self.idx = -1
		self.f = f
		self.start = None
		self.data_size = 0
		self.data_position = None
		self.optimised_image = False
		self.is_compressed = False
		self.has_handle = False
		self.handle = -1
		self.mode = 0
		self.is_new_item = False
		self.new_game = False
		self.product_build = None
		self.ccn_game = False

		self.head_size = 0
		self.head_data = None
		self.head_expected_size = 0
		self.body_expected_size = 0
		self.is_new_item = False

		self.checksum = None
		self.reference = None
		self.gmode: defs.GraphicModes = None
		self.point_size: int = None
		self.enc_flags: defs.ImageEncodingFlag = None
		self.sizex = None
		self.sizey = None

		self.hotspotx = None
		self.hotspoty = None
		self.actionx = None
		self.actiony = None
		self.col_transparent = None

		self.padding = None
		self.alpha_padding = None

		self.experiment_show = None

	def __repr__(self):
		return 'PretzImageItem(idx=%d, handle=%d, size=%d (0x%x))' % (self.idx, self.handle, self.data_size, self.data_size)

	def decode(self):
		f = self.f
		max_size = 176
		if self.new_game:
			max_size += 80
		else:
			max_size += 16

		# decode_body ()
		f.seek(self.data_position, os.SEEK_SET)
		if not self.new_game:
			match self.mode:
				case 0:
					data = f.read(self.data_size)
				case 1:
					magic = f.read(1)
					length = cast(list[int], struct.unpack('<H', f.read(2)))[0]
					if magic == 0x0f and length == self.body_expected_size:
						data = f.read(max_size)
					else:
						data = f.read(self.data_size)
						data = zips.decompress(data)
				case _:
					raise Exception("no decoder")
		else:
			match self.mode:
				case  4:
					raise Exception("not implemeted")
				case 3, 2:
					raise Exception("not implemeted")
				case 1:
					raise Exception("not implemeted")
				case _:
					data = f.read(self.data_size)
					if len(data) > 0 and data[0] == 0x78:
						#print("compress level =", zips.compress_level(data))
						data = zips.decompress(data)
						#if len(data) > max_size:
					else:
						pass
		# end -- decode body
		return data

	def get_data(self):
		f = self.f
		if self.optimised_image:
			self.data_position = f.tell()

			# decode_head (head_size)
			raise Exception('not implemented')

		d = BytesIO(self.decode())
		checksum = 0
		if not self.new_game:
			checksum = cast(list[int], struct.unpack('<H', d.read(2)))[0]
		else:
			checksum = cast(list[int], struct.unpack('<L', d.read(4)))[0]
		#print('checksum = 0x%x' % (checksum,))
		self.checksum = checksum

		reference = cast(list[int], struct.unpack('<L', d.read(4)))[0]
		#print('reference = ', reference)
		self.reference = reference

		if self.optimised_image:
			d.seek(4, os.SEEK_CUR)

		data_size = struct.unpack('<L', d.read(4))[0]
		#print('data size = ', data_size)

		self.sizex, self.sizey, gmode_num, flags_num = struct.unpack('<HHBB', d.read(6))
		self.enc_flags = defs.ImageEncodingFlag(flags_num)

		padding = None
		match gmode_num:
			case 2, 3:
				self.gmode = defs.GraphicModes.RGB8
				self.point_size = 1
				if defs.ImageEncodingFlag.RLET in self.enc_flags:
					padding = self.sizex % 2
				elif self.optimised_image:
					padding = self.sizex % 2
				elif self.ccn_game:
					padding = (4 - (self.sizex % 4)) % 4
				elif not self.new_game:
					padding = self.sizex % 2
				elif self.product_build < 280:
					padding = self.sizex % 2
				else:
					padding = self.sizex % 2
			case 4:
				self.gmode = defs.GraphicModes.BGR24
				self.point_size = 3
				if defs.ImageEncodingFlag.RLET in self.enc_flags:
					padding = (self.sizex * 3) % 2
				elif self.optimised_image:
					padding = (self.sizex * 3) % 2
				elif self.ccn_game:
					padding = (4 - ((self.sizex*3) % 4)) % 4
				elif not self.new_game:
					padding = ((self.sizex * 3) % 2) * 3
				elif self.product_build < 280:
					padding = ((self.sizex * 3) % 2) * 3
				else:
					padding = (self.sizex % 2) * 3
			case 6:
				self.gmode = defs.GraphicModes.RGB15
				self.point_size = 2
				padding = 0
			case 7:
				self.gmode = defs.GraphicModes.RGB16
				self.point_size = 2
				padding = 0
			case 8:
				self.gmode = defs.GraphicModes.BGRA32
				self.point_size = 4
				padding = 0
			case _:
				raise Exception("unknown gmode " +  gmode_num)

		#print('x=',sizex, 'y=',sizey, 'gmode=', gmode, 'flags=', list(flags))

		if self.new_game:
			unknown = cast(list[int], struct.unpack('<H', d.read(2)))[0]
			#print('unknown =', unknown)

		self.hotspotx, self.hotspoty, self.actionx, self.actiony = struct.unpack('<HHHH', d.read(8))
		#print('hotx=',hotspotx, 'hoty=', hotspoty, 'actx=', actionx, 'acty=', actiony)

		if self.new_game:
			self.col_transparent = struct.unpack('<BBBB', d.read(4))
			#print("transparent =",transparent_r, transparent_g, transparent_b, transparent_a)

		if self.optimised_image:
			if f.tell() != self.data_position:
				raise Exception("mismatch position")
			body_data = f.read(data_size)
			self.data_position = 0
			corrected_size = f.tell() - self.start

			raise Exception('not implelented')

		alpha_padding = 0
		if not self.ccn_game:
			alpha_padding = (4 - (self.sizex % 4)) % 4

		self.padding = padding
		self.alpha_padding = alpha_padding
		#pixel_data_pos = d.tell()
		pixel_data = d.read()
		pixel_data_size = len(pixel_data)
		#print('pixel data size = %d  (0x%08x)' %  (pixel_data_size, pixel_data_size))

		return pixel_data

	def get_pixels(self):
		d = self.get_data()
		pixels = np.zeros((self.sizey, self.sizex, 4), dtype=np.uint8)
		d_remain = None

		print('gmode =', self.gmode, 'enc_flags =', self.enc_flags, 'size =', self.sizex, self.sizey, 'padding =', self.padding, self.alpha_padding)
		if self.gmode is defs.GraphicModes.JPEG:
			raise Exception("noti mplemented read JPEG")
			# convertto rgba32 using stbi
		else:
			if self.enc_flags & (defs.ImageEncodingFlag.RLE | defs.ImageEncodingFlag.RLEW |
				              defs.ImageEncodingFlag.RLET)  != 0:
				raise Exception("not implemented read RLE")
			else:
				#ReadRGB()
				stride = (self.sizex * self.point_size) + self.padding
				pixel_end = stride * self.sizey
				if self.padding == 0:
					stride = 0
				#print('stride =', stride)

				d_remain = d[pixel_end:]
				p = BytesIO(d[:pixel_end])
				i = 0
				for y in range(0, self.sizey):
					for x in range(0, self.sizex):
						if self.gmode is defs.GraphicModes.BGR24:
							b,g,r = struct.unpack('<BBB', p.read(3))
							pixels[y, x] = [r, g, b, 255]
						i += 1
					if self.padding != 0:
						p.seek(self.padding, os.SEEK_CUR)

		if defs.ImageEncodingFlag.RGBA in self.enc_flags:
			# we already read the alpha data with the colour data
			pass
		elif defs.ImageEncodingFlag.ALPHA in self.enc_flags:
			# ReadAlpha
			#print(len(d_remain))
			#print((self.sizex + self.alpha_padding) * self.sizey)
			p = BytesIO(d_remain)
			i = 0
			for y in range(0, self.sizey):
				for x in range(0, self.sizex):
					a = p.read(1)
					pixels[y, x][3] = ord(a)
					i += 1
				if self.alpha_padding != 0:
					p.seek(self.alpha_padding, os.SEEK_CUR)

		elif self.col_transparent is not None:
			#print(self.col_transparent)
			# set alpha to col_transparent.a if pixel.rgb = col_transparent.rgb
			i = 0
			for y in range(0, self.sizey):
				for x in range(0, self.sizex):
					if np.all(np.equal(pixels[y, x][:3], self.col_transparent[:3])):
						pixels[y, x][3] = self.col_transparent[3]
						i += 1
		else:
			# set alhpa to 255 on each pixels"
			pass

		return pixels

class ImageBank:
	def __init__(self, f: typing.BinaryIO):
		self.f = f
		self.items: list[PretzImageItem] = []

	def parse(self):
		f = self.f
		count = cast(list[int], struct.unpack('<L', f.read(4)))[0]
		print('image count =', count)

		for i in range(0, count):
			start = f.tell()
			item = self.analyze_item(start)
			item.idx = i
			self.items.append(item)
			print(item)

		print('last pos =', f.tell())

	def analyze_item(self, start) -> PretzImageItem:
		f = self.f
		f.seek(start, os.SEEK_SET)
		item = PretzImageItem(self.f)
		item.start = start
		item.product_build = clickPretz.pam_section.product_build
		item.ccn_game = clickPretz.ccn_game

		optims = cast(list[int], struct.unpack('<LL', f.read(8)))
		item.optimised_image = optims[1] == 0xffffffff
		#print('optimised_image =', item.optimised_image)

		f.seek(-8, os.SEEK_CUR)
		item.has_handle = True
		item.head_size = 0

		# TODO: if ccn
		# item.is_compressed = True
		# head_size = 10
		# else:
		if item.optimised_image:
			item.head_size = 0x24
			item.is_compressed = False
			raise Exception("optimissed image not yet implemented")
		else:
			item.is_compressed = True

		set_body_size = None

		# read init
		item.new_game = clickPretz.pam_section.new_game
		item.mode = 0

		# read head(head_size, item.has_handle)
		if item.has_handle:
			item.handle = cast(list[int], struct.unpack('<L', f.read(4)))[0]
			if not item.optimised_image and item.new_game and item.product_build >= 284:
				item.handle -= 1
		else:
			item.handle = 0xffffffff
		#print('handle =', item.handle)

		item.is_new_item = cast(list[int], struct.unpack('<L', f.read(4)))[0] == 0xffffffff
		#print('is_new_item = %s' % (item.is_new_item,))
		f.seek(-4, os.SEEK_CUR)

		if item.new_game and item.head_size > 0:
			item.head_data = f.read(item.head_size)
			item.head_expected_size = 0
			#print('head_data =', item.head_data)

		# read body(item.is_compressed, set_body_size)
		if item.is_new_item:
			item.mode = 4
			item.is_compressed =  False

		if not item.new_game or item.is_compressed:
			item.body_expected_size = cast(list[int], struct.unpack('<L', f.read(4)))[0]
			#print('body_expected_size =', item.body_expected_size)
		else:
			item.body_expected_size = 0

		if set_body_size is not None:
			item.data_size = set_body_size
		elif not item.new_game:
			raise Exception('noti mplemented')
		elif not item.is_new_item:
			item.data_size = cast(list[int], struct.unpack('<L', f.read(4)))[0]
			item.data_position = f.tell()

		#print('item data size = %d (0x%08x)' % (item.data_size, item.data_size))
		f.seek(item.data_size, os.SEEK_CUR)

		# hack because one of MMF1.5 or tinf_uncompress is a bitch
		if not item.new_game:
			item.mode = 1

		return item

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print("missing argument")
		sys.exit(1)

	select_number = 0
	if len(sys.argv) >= 3:
		select_number = int(sys.argv[2])

	filename = sys.argv[1]
	clickPretz = ClickPretz(filename)
	clickPretz.analyze()
	#click_Pretz.wwww_section.testing(False)
	#clickPretz.pam_section.testing(True)
	clickPretz.pam_section.testing_images(select_number)
