from typing import BinaryIO
from io import BytesIO
from struct import unpack
import os, re

from . import  clickp

def SplitPath(path):
	return re.split(r'/|\\', path)

class Item:
	def __init__(self, f: BinaryIO, unicode: bool, parent):
		self.f = f
		self.idx: int = None
		self.unicode = unicode
		self.name_len: int = None
		self.name: str = None
		self.data_len: int = None
		self.data_pos: int = None
		self._parent: BinaryBank = parent

	def parse(self):
		f = self.f
		self.name_len = unpack('<H', f.read(2))[0]

		if self.unicode:
			name_wide = f.read(self.name_len *2)
			self.name = name_wide.decode('utf-16')
		else:
			self.name = f.read(self.name_len)

		self.data_len = unpack('<L', f.read(4))[0]
		self.data_pos = f.tell()

		f.seek(self.data_len, os.SEEK_CUR)

	def get_data(self):
		f = self.f
		f.seek(self.data_pos, os.SEEK_SET)
		data = f.read(self.data_len)
		return data

	def cache_name(self):
		fname = SplitPath(self.name)[-1]
		fname, fext = os.path.splitext(fname)
		if fname != '':
			fname += ';'

		return "out/pamu/binary_files;%d.d/%s%d%s" % (self._parent.idx, fname, self.idx, fext)

	def dump(self):
		fname = self.cache_name()
		path = SplitPath(fname)[:-1]
		try:
			os.mkdir(os.path.join(*path))
		except OSError as err:
			print(err)
		with open(fname, 'wb') as f:
			f.write(self.get_data())


class BinaryBank:
	def __init__(self, f: BinaryIO, unicode: bool):
		self.idx: int = None
		self.f = f
		self.unicode = unicode
		self.items: list[Item] = []

	def parse(self):
		f = self.f
		count  = unpack('<L', f.read(4))[0]
		for i in range(0, count):
			item = Item(f, self.unicode, self)
			item.idx = i
			item.parse()
			self.items.append(item)

			print(item.idx, item.name)

	def get_item(self, idx) -> Item:
		return self.items[idx]


def testing_binfiles(reader: clickp.FileReader, select_number: int):
	item = reader.pam_section.get_item(83)
	f = BytesIO(item.get_data())
	binbank = BinaryBank(f, reader.pam_section.unicode)
	binbank.idx = item.idx
	binbank.parse()

	select_numbers = list([select_number])
	if select_number == -1:
		select_numbers = range(0, len(binbank.items))

	print('select_number =', select_number)
	for select_number in select_numbers:
		item = binbank.get_item(select_number)
		print(item.cache_name())
		item.dump()
