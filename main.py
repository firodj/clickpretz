import os, sys

from PIL import Image
import numpy as np
from struct import unpack
from io  import BytesIO

from pretz import defs, zips, strs, crypts, wwww, pamu, imgs, clickp, bins




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
	#clickPretz.wwww_section.testing(True)
	#clickPretz.pam_section.testing(True)
	#imgs.testing_images(clickPretz, select_number)
	#print(clickPretz.pam_section.get_item(3))
	bins.testing_binfiles(clickPretz, select_number)
