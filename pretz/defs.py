from enum import Enum, IntFlag
from typing import  Final

class ImageEncodingFlag(IntFlag):
	RLE = 1
	RLEW = 2
	RLET = 4
	LZX = 8
	ALPHA = 0x10
	ACE = 0x20
	MAC = 0x40
	RGBA = 0x80

class GraphicModes(Enum):
	RGB8 = 'rgb8'
	BGR24 = 'bgr24'
	RGB15 = 'rgb15'
	RGB16 = 'rgb16'
	BGRA32 =  'bgra32'
	JPEG = 'jpeg'

CHUNK_TYPES: Final[dict[int,str]] = {
	0x0302: 'entry',
	0x1122: 'vitalise_preview',
	0x2223: 'header',
	0x2224: 'title',
	0x2225: 'author',
	0x2226: 'menu',
	0x2227: 'extra_path',
	0x2228: 'extensions',
	0x2229: 'object_bank', # frameitems
	0x222A: 'global_events',
	0x222B: 'frame_handles',
	0x222C: 'extra_data',
	0x222D: 'additional_extensions',
	0x222E: 'project_path',
	0x222F: 'output_path',
	0x2230: 'app_doc',
	0x2231: 'other_extension',
	0x2232: 'global_values',
	0x2233: 'global_strings',
	0x2234: 'extensions_list',
	0x2235: 'icon',
	0x2236: 'demo_version',
	0x2237: 'security_number',
	0x2238: 'binary_files',
	0x2239: 'menu_images',
	0x223A: 'about',
	0x223B: 'copyright',
	0x223C: 'global_value_names',
	0x223D: 'global_string_names',
	0x223E: 'movement_extensions',
	0x223F: 'unknown8',
	0x223F: 'object_bank2', # frameitems2
	0x2240: 'exe_only',
	#0x2241
	0x2242: 'protection',
	0x2243: 'shaders',
	#0x2244
	0x2245: 'extended_header',
	0x2246: 'spacer',
	0x224D: 'frame_bank', # FRAMEHANDLES might be broken
	0x224F: 'chunk224F',
	0x2251: 'title2',
	0x2253: 'chunk2253',
	0x2254: 'object_names',
	0x2255: 'chunk2255',
	0x2256: 'two_five_plus_object_properties',
	0x2257: 'chunk2257',
	0x2258: 'font_meta',
	0x2259: 'font_chunk',
	0x225A: 'shaders2',
	0x3333: 'frame',
	0x3334: 'frame_header',
	0x3335: 'frame_name',
	0x3336: 'frame_password',
	0x3337: 'frame_palette',
	0x3338: 'frame_object_instances',
	0x3339: 'frame_fade_in_frame',
	0x333A: 'frame_fade_out_frame',
	0x333B: 'frame_fade_in',
	0x333C: 'frame_fade_out',
	0x333D: 'frame_events',
	0x333E: 'frame_play_header',
	0x333F: 'frame_additional_items',
	0x3340: 'frame_additional_items_instances',
	0x3341: 'frame_layers',
	0x3342: 'frame_virtual_size',
	0x3343: 'demo_file_path',
	0x3344: 'random_seed',
	0x3345: 'frame_layer_effect',
	0x3346: 'frame_bluray',
	0x3347: 'movement_timer_base',
	0x3348: 'mosaic_image_table',
	0x3349: 'frame_effects',
	0x334A: 'frame_iphone_options',
	0x334C: 'frame_chunk334C',
	0x4150: 'pa_error',
	0x4444: 'object_header',
	0x4445: 'object_name',
	0x4446: 'object_properties',
	0x4447: 'object_chunk4447',
	0x4448: 'object_effect',
	0x5555: 'image_handles',
	0x5556: 'font_handles',
	0x5557: 'sound_handles',
	0x5558: 'music_handles',
	0x6665: 'bank_offsets',
	0x6666: 'image_bank',
	0x6667: 'font_bank',
	0x6668: 'sound_bank',
	0x6669: 'music_bank',
	0x7EEE: 'fusion_3_seed',
	0x7F7F: 'last',
}

def chunk_type(chunk_id):
	if chunk_id in CHUNK_TYPES:
		return CHUNK_TYPES[chunk_id]
	return ''
