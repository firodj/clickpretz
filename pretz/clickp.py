import os, sys
import pefile
from . import wwww, pamu

class FileReader:
	def __init__(self, filename):
		self.filename = filename
		self.ccn_game: bool = None
		self.new_game: bool = None
		self.wwww_section = None
		self.pam_section = None
		self.f = None

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
		self.f = open(self.filename + ".app", "rb")
		f = self.f

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

		self.pam_section = pamu.Section(f, entry_start_ofs)
		self.pam_section.new_game = self.new_game
		self.pam_section.ccn_game = self.ccn_game
		self.pam_section.parse()

class FileWriter:
	def __init__(self):
		self.ccn_game = False
		self.new_game = True
