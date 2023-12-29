from typing import BinaryIO
import os

class String:
	def __init__(self, f: BinaryIO, is_unicode):
		self.f = f
		self.encoding = 'utf-8'
		if is_unicode:
			self.encoding = 'utf-16'
		self._len = None
	def __str__(self):
		self.f.seek(0, os.SEEK_SET)
		return self.f.read().decode(self.encoding)
	def __len__(self):
		if self._len is None:
			self._len = self.f.seek(0, os.SEEK_END)
		return self._len
	def __iter__(self):
		self.f.seek(0, os.SEEK_SET)
		return self
	def __next__(self):
		b = self.f.read(1)
		if len(b) > 0:
			return b[0]
		raise StopIteration