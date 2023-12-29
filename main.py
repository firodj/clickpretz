import os, sys

from PIL import Image
import numpy as np
from struct import unpack
from io  import BytesIO

from pretz import defs, zips, strs, crypts, wwww, pamu, imgs, clickp

#def ColorFrom32bitRGBA(d: typing.BinaryIO):
#	return struct.unpack('<BBBB', d.read(4))
def testing_binfiles(reader: clickp.FileReader, select_number: int):
	binfiles = reader.pam_section.get_item(83)
	f = BytesIO(binfiles.get_data())
	count  = unpack('<L', f.read(4))[0]
	for i in range(0, count):
		name_len = unpack('<H', f.read(2))[0]

		if reader.pam_section.unicode:
			name_wide = f.read(name_len *2)
			name = name_wide.decode('utf-16')
		else:
			name = f.read(name_len)

		print(i, name)

		data_len = unpack('<L', f.read(4))[0]
		if select_number == i:
			data = f.read(data_len)
			print(data)
			break
		else:
			f.seek(data_len, os.SEEK_CUR)


def testing_images(reader: clickp.FileReader, select_number: int):
	#with reader.pam_section.items[77].cache_file() as f:
	imageBank = reader.pam_section.get_item(77)
	#imgs.ImageBank(f, reader.pam_section.product_build, reader.new_game, reader.ccn_game)
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

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print("missing argument")
		sys.exit(1)

	select_number = 0
	if len(sys.argv) >= 3:
		select_number = int(sys.argv[2])

	filename = sys.argv[1]
	clickPretz = clickp.FileReader(filename)
	clickPretz.analyze()
	#click_Pretz.wwww_section.testing(False)
	#clickPretz.pam_section.testing(True)
	#testing_images(clickPretz, select_number)
	#print(clickPretz.pam_section.get_item(3))
	testing_binfiles(clickPretz, select_number)
