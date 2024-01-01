import os, sys

from PIL import Image
import numpy as np
from struct import unpack
from io  import BytesIO

from pretz import defs, zips, strs, crypts, wwww, pamu, imgs, clickp, bins

def testing_writer():
	clickCrotz = clickp.FileWriter()
	fw = BytesIO()

	wwww_section = wwww.Section(fw, 0)
	wwww_section.glob()

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
	#bins.testing_binfiles(clickPretz, select_number)
	testing_writer()
