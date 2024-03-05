# Based on https://gist.github.com/DavidBuchanan314/93de9d07f7fab494bcdf17c2bd6cef02

import zlib
import sys

if len(sys.argv) != 2:
	print(f"USAGE: {sys.argv[0]} cropped.png/jpg")
	exit()

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

def parse_png_chunk(stream):
	size = int.from_bytes(stream.read(4), "big")
	ctype = stream.read(4)
	body = stream.read(size)
	csum = int.from_bytes(stream.read(4), "big")
	assert(zlib.crc32(ctype + body) == csum)
	return ctype, body

def valid_png_iend(trailer):
	iend_pos = len(trailer) - 8
	iend_size = int.from_bytes(trailer[iend_pos-4:iend_pos], "big")
	iend_csum = int.from_bytes(trailer[iend_pos+4:iend_pos+8], "big")
	return iend_size == 0 and iend_csum == 0xAE426082

def parse_png(f_in):
	magic = f_in.read(len(PNG_MAGIC))
	assert(magic == PNG_MAGIC)
	# find end of cropped PNG
	while True:
		ctype, body = parse_png_chunk(f_in)
		if ctype == b"IEND":
			break

	# grab the trailing data
	trailer = f_in.read()

	if trailer and valid_png_iend(trailer):
		print(sys.argv[1])

def parse_jpeg(f_in):
	SOI_marker = f_in.read(2)
	assert(SOI_marker == b"\xFF\xD8")
	APP0_marker = f_in.read(2)
	assert(APP0_marker == b"\xFF\xE0")
	APP0_size = int.from_bytes(f_in.read(2), "big")
	APP0_body = f_in.read(APP0_size - 2)
	assert(APP0_body[:4] == b"JFIF")
	
	f_in.seek(0,0)
	file = f_in.read()
	EOI_marker_pos = file.index(b"\xFF\xD9")

	assert(EOI_marker_pos)
	
	cropped = file[:EOI_marker_pos + 2]
	trailer = file[EOI_marker_pos + 2:]

	if trailer and trailer[-2:] == b"\xFF\xD9":
		print(sys.argv[1])

f_in = open(sys.argv[1], "rb")
start = f_in.read(2)
f_in.seek(0,0)

if start == b"\x89P":
	parse_png(f_in)
elif start == b"\xFF\xD8":
	parse_jpeg(f_in)
else:
	print("File doesn't appear to be jpeg or png.")