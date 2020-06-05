#!/usr/bin/env python3

import re
from struct import unpack

def read_file(filename: str, text: bool = False, encoding: str = "UTF8") -> (bytes, str):
	"""
	Read all the data in a specified file
	:param filename: The file to read from
	:param text: Whether or not to read as text
	:param encoding: The encoding to use if the text param is true
	:return: bytes or text depending on the text param
	"""
	with open(filename, "r" if text else "rb", encoding=encoding) as f:
		data = f.read()
	return data

def main() -> None:
	text = read_file("APK/2.41.1/dumped/sharedassets0.assets/Assets/TextAsset/Localization.bytes", True)

	set_name_exp = re.compile(r"SetName-([\w\d]{0,}?),")
	costume_ids = set_name_exp.findall(text)
	print("COSTUME_IDS = [")
	for x in costume_ids:
		print("\t\"" + x + "\"")
	print("]")

	card_level_exp = re.compile(r"CardLevel(\d+),")
	card_levels = [int(x) for x in card_level_exp.findall(text)]
	max_level = card_levels.pop(-1) - 1
	for level in card_levels:
		if level <= max_level:
			print("CardLevel" + str(level))

	with open("APK/2.41.1/Managed/Metadata/global-metadata.dat", "rb") as f:
		f.seek(0x764AD9)  # IDA 0x15D1044 -> 0BAC7EE95041DEEE3706B4D5EC9AE5E5E42DB235 -> numArray1 -> Leveling Tokens
		for level in range(max_level + 1):
			(v,) = unpack("<I", f.read(4))
			print(f"{level} = {v}")

if __name__ == "__main__":
	main()