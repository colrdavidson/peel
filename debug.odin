package peel

import "core:fmt"
import "core:os"
import "core:mem"
import "core:strings"
import "core:intrinsics"
import "core:sort"
import "core:slice"
import "core:runtime"
import "core:io"
import "core:unicode/utf8"
import "core:encoding/varint"

/*
Handy References:
- https://refspecs.linuxbase.org/elf/elf.pdf
- http://man7.org/linux/man-pages/man5/elf.5.html
- http://dwarfstd.org/doc/DWARF4.pdf
- https://wiki.osdev.org/DWARF
*/

ELFCLASS64 :: 2
ELFDATA2LSB :: 1
EM_X86_64 :: 62

ET_EXEC :: 2
ET_DYN  :: 3
ET_CORE :: 4

SHT_NULL     :: 0
SHT_PROGBITS :: 1
SHT_SYMTAB   :: 2
SHT_STRTAB   :: 3
SHT_RELA     :: 4
SHT_HASH     :: 5
SHT_DYNAMIC  :: 6

ELF64_Header :: struct #packed {
	magic: [4]u8,
	class: u8,
	endian: u8,
	hdr_version: u8,
	pad: [9]u8,

	type: u16,
	machine: u16,
	version: u32,
	entry: u64,
	program_hdr_offset: u64,
	section_hdr_offset: u64,
	flags: u32,
	ehsize: u16,
	program_hdr_entry_size: u16,
	program_hdr_num: u16,
	section_entry_size: u16,
	section_hdr_num: u16,
	section_hdr_str_idx: u16,
}

ELF64_Section_Header :: struct #packed {
	name: u32,
	type: u32,
	flags: u64,
	addr: u64,
	offset: u64,
	size: u64,
	link: u32,
	info: u32,
	addr_align: u64,
	entry_size: u64,
}

DWARF32_CU_Header :: struct #packed {
	unit_length: u32,
	version: u16,
	abbrev_offset: u32,
	address_size: u8,
}

Block :: struct {
	id: int,
	type: Dw_Tag,
	attrs: map[Dw_At]Attr_Entry,

	parent: ^Block,
	children: [dynamic]^Block,
}

Attr_Data :: union {
	[]u8,
	i64,
	u64,
	u32,
	u16,
	u8,
	string,
	bool,
}

Attr_Entry :: struct {
	form: Dw_Form,
	data: Attr_Data,
}

Abbrev_Unit :: struct {
	id: u64,
	cu_idx: int,
	type: Dw_Tag,

	has_children: bool,
	attrs_buf: []u8,
}


Dw_Form :: enum {
	addr         = 0x01,
	block2       = 0x03,
	block4       = 0x04,
	data2        = 0x05,
	data4        = 0x06,
	data8        = 0x07,
	str          = 0x08,
	block        = 0x09,
	block1       = 0x0a,
	data1        = 0x0b,
	flag         = 0x0c,
	sdata        = 0x0d,
	strp         = 0x0e,
	udata        = 0x0f,
	ref_addr     = 0x10,
	ref1         = 0x11,
	ref2         = 0x12,
	ref4         = 0x13,
	ref8         = 0x14,
	ref_udata    = 0x15,
	indirect     = 0x16,
	sec_offset   = 0x17,
	exprloc      = 0x18,
	flag_present = 0x19,
}

Dw_At :: enum {
	sibling            = 0x01,
	location           = 0x02,
	name               = 0x03,
	ordering           = 0x09,
	byte_size          = 0x0b,
	bit_offset         = 0x0c,
	bit_size           = 0x0d,
	stmt_list          = 0x10,
	low_pc             = 0x11,
	high_pc            = 0x12,
	language           = 0x13,
	discr              = 0x15,
	discr_value        = 0x16,
	visibility         = 0x17,
	imprt              = 0x18,
	string_length      = 0x19,
	common_ref         = 0x1a,
	comp_dir           = 0x1b,
	const_val          = 0x1c,
	containing_type    = 0x1d,
	default_type       = 0x1e,
	inlne              = 0x20,
	is_optional        = 0x21,
	lower_bound        = 0x22,
	producer           = 0x25,
	prototyped         = 0x27,
	return_addr        = 0x2a,
	start_scope        = 0x2c,
	bit_stride         = 0x2e,
	upper_bound        = 0x2f,
	abstract_origin    = 0x31,
	accessibility      = 0x32,
	address_class      = 0x33,
	artificial         = 0x34,
	base_types         = 0x35,
	calling_convention = 0x36,
	count              = 0x37,
	data_mem_location  = 0x38,
	decl_column        = 0x39,
	decl_file          = 0x3a,
	decl_line          = 0x3b,
	declaration        = 0x3c,
	discr_list         = 0x3d,
	encoding           = 0x3e,
	external           = 0x3f,
	frame_base         = 0x40,
	friend             = 0x41,
	identifier_case    = 0x42,
	macro_info         = 0x43,
	namelist_item      = 0x44,
	priority           = 0x45,
	segment            = 0x46,
	specification      = 0x47,
	static_link        = 0x48,
	type               = 0x49,
	use_location       = 0x4a,
	variable_parameter = 0x4b,
	virtuality         = 0x4c,
	vtable_elem_loc    = 0x4d,
	allocated          = 0x4e,
	associated         = 0x4f,
	data_location      = 0x50,
	byte_stride        = 0x51,
	entry_pc           = 0x52,
	use_UTF8           = 0x53,
	extension          = 0x54,
	ranges             = 0x55,
	trampoline         = 0x56,
	call_column        = 0x57,
	call_file          = 0x58,
	call_line          = 0x59,
	description        = 0x5a,
	binary_scale       = 0x5b,
	decimal_scale      = 0x5c,
	small              = 0x5d,
	decimal_sign       = 0x5e,
	digit_count        = 0x5f,
	picture_string     = 0x60,
	mutable            = 0x61,
	threads_scaled     = 0x62,
	explicit           = 0x63,
	object_pointer     = 0x64,
	endianity          = 0x65,
	linkage_name       = 0x6e,

	// DWARF 5
	noreturn           = 0x87,
	alignment          = 0x88,

	// GNU extensions
	GNU_pubnames       = 0x2134,
}

Dw_Tag :: enum {
	array_type         = 0x01,
	class_type         = 0x02,
	entry_point        = 0x03,
	enum_type          = 0x04,
	formal_parameter   = 0x05,
	imported_decl      = 0x08,
	label              = 0x0a,
	lexical_block      = 0x0b,
	member             = 0x0d,
	pointer_type       = 0x0f,
	ref_type           = 0x10,
	compile_unit       = 0x11,
	string_type        = 0x12,
	struct_type        = 0x13,
	subroutine_type    = 0x15,
	typedef            = 0x16,
	union_type         = 0x17,
	unspec_params      = 0x18,
	variant            = 0x19,
	common_block       = 0x1a,
	common_incl        = 0x1b,
	inheritance        = 0x1c,
	inlined_subroutine = 0x1d,
	module             = 0x1e,
	ptr_to_member_type = 0x1f,
	set_type           = 0x20,
	subrange_type      = 0x21,
	with_stmt          = 0x22,
	access_decl        = 0x23,
	base_type          = 0x24,
	catch_block        = 0x25,
	const_type         = 0x26,
	constant           = 0x27,
	enumerator         = 0x28,
	file_type          = 0x29,
	friend             = 0x2a,
	subprogram         = 0x2e,
	variable           = 0x34,
	program            = 0xff,
}


panic :: proc(fmt_in: string, args: ..any) {
	fmt.printf(fmt_in, ..args)
	os.exit(1)
}

slice_to_type :: proc(buf: []u8, $T: typeid) -> (T, bool) #optional_ok {
    if len(buf) < size_of(T) {
        return {}, false
    }
    return intrinsics.unaligned_load((^T)(raw_data(buf))), true
}

sort_entries_by_length :: proc(m: ^$M/map[$K]$V, loc := #caller_location) {
	Entry :: struct {
		hash:  uintptr,
		next:  int,
		key:   K,
		value: V,
	}

	header := runtime.__get_map_header(m)
	entries := (^[dynamic]Entry)(&header.m.entries)
	slice.sort_by(entries[:], proc(a: Entry, b: Entry) -> bool { return len(a.value) < len(b.value) })
	runtime.__dynamic_map_reset_entries(header, loc)
}

load_elf :: proc(binary_blob: []u8) -> map[string][]u8 {
	prog_hdr, rk := slice_to_type(binary_blob, ELF64_Header)
	if !rk {
		panic("Invalid ELF file!\n")
	}

	elf_magic := []u8{ 0x7f, 'E', 'L', 'F' }
	if mem.compare(prog_hdr.magic[:], elf_magic) != 0 {
		panic("Invalid ELF file!\n")
	}

	if prog_hdr.hdr_version != 1 {
		panic("Your ELF is stupid\n")
	}

	if prog_hdr.class != ELFCLASS64 ||
	   prog_hdr.endian != ELFDATA2LSB ||
	   prog_hdr.machine != EM_X86_64 {
		panic("TODO only supports x86_64!\n")
	}

	if prog_hdr.type == ET_CORE {
		panic("TODO add coredump support!\n")
	}

	if !(prog_hdr.type == ET_EXEC || prog_hdr.type == ET_DYN) {
		panic("ELF file is not executable!\n")
	}

	if prog_hdr.section_hdr_offset > u64(len(binary_blob)) {
		panic("Invalid section header offset!\n")
	}

	str_table_hdr_idx := prog_hdr.section_hdr_offset + u64(prog_hdr.section_hdr_str_idx * prog_hdr.section_entry_size)
	if str_table_hdr_idx > u64(len(binary_blob)) {
		panic("Invalid str table header index!\n")
	}

	str_table_hdr, strk := slice_to_type(binary_blob[str_table_hdr_idx:], ELF64_Section_Header)
	if !strk {
		panic("Invalid ELF file!\n")
	}

	if str_table_hdr.type != SHT_STRTAB {
		panic("Executable string table is borked!\n")
	}

	if str_table_hdr.offset > u64(len(binary_blob)) {
		panic("Invalid str table offset!\n")
	}

	sections := make(map[string][]u8)
	for i := 0; i < int(prog_hdr.section_hdr_num); i += 1 {
		section_idx := prog_hdr.section_hdr_offset + u64(i * int(prog_hdr.section_entry_size))
		section_hdr, sk := slice_to_type(binary_blob[section_idx:], ELF64_Section_Header)
		if !sk {
			panic("Invalid ELF file!\n")
		}

		if section_hdr.offset > u64(len(binary_blob)) {
			panic("Invalid section offset!\n")
		}

		section_name_blob := binary_blob[str_table_hdr.offset + u64(section_hdr.name):]
		if section_name_blob[0] == 0 {
			continue
		}

		section_name := strings.clone_from_cstring(cstring(raw_data(section_name_blob)))
		sections[section_name] = binary_blob[section_hdr.offset:section_hdr.offset+section_hdr.size]
	}

	if !(".debug_abbrev" in sections &&
	     ".debug_line" in sections &&
	     ".debug_info" in sections) {
		panic("TODO currently can't support binaries without debug symbols!\n")
	}

	return sections
}

print_abbrev_table :: proc(entries: []Abbrev_Unit) {
	for i := 0; i < len(entries); i += 1 {
		entry := entries[i]
		fmt.printf("Entry ID: %d || CU: %d\n", entry.id, entry.cu_idx)
		fmt.printf("- type: %s 0x%x\n", entry.type, int(entry.type))
		fmt.printf("- children: %s\n", (entry.has_children) ? "yes" : "no")

		for j := 0; j < len(entry.attrs_buf); {
			attr_name, leb_size_1, err_1 := varint.decode_uleb128(entry.attrs_buf[j:])
			if err_1 != nil {
				panic("Invalid attr name!\n")
			}
			j += leb_size_1

			attr_form, leb_size_2, err_2 := varint.decode_uleb128(entry.attrs_buf[j:])
			if err_2 != nil {
				panic("Invalid attr form!\n")
			}
			j += leb_size_2

			if attr_name == 0 && attr_form == 0 {
				break
			}

			fmt.printf("(0x%x) %s (0x%x) %s\n", attr_name, Dw_At(attr_name), attr_form, Dw_Form(attr_form))
		}
	}
}

print_block_tree :: proc(node: ^Block, depth: int = 0) {
	pad_buf := [4096]u8{}
	b := strings.builder_from_slice(pad_buf[:])
	for i := 0; i < depth; i += 1 {
		strings.write_string(&b, "  ")
	}

	fmt.printf("%s%d | %s\n", strings.to_string(b), node.id, node.type)
	for key, value in node.attrs {
		fmt_result : string
		#partial switch in value.data {
		case i64:
			fmt.printf("%s - %s -- %d\n", strings.to_string(b), key, value.data)
		case u64:
			fmt.printf("%s - %s -- %d\n", strings.to_string(b), key, value.data)
		case u32:
			fmt.printf("%s - %s -- %d\n", strings.to_string(b), key, value.data)
		case u16:
			fmt.printf("%s - %s -- %d\n", strings.to_string(b), key, value.data)
		case u8:
			fmt.printf("%s - %s -- %d\n", strings.to_string(b), key, value.data)
		case []u8:
			fmt.printf("%s - %s -- %x\n", strings.to_string(b), key, value.data)
		case bool:
			fmt.printf("%s - %s -- %t\n", strings.to_string(b), key, value.data)
		case string:
			fmt.printf("%s - %s -- %s\n", strings.to_string(b), key, value.data)
		}
	}

	for i := 0; i < len(node.children); i += 1 {
		print_block_tree(node.children[i], depth + 1)
	}
}

parse_attr_data :: proc(sections: ^map[string][]u8,  form: Dw_Form, data: []u8) -> (entry: Attr_Data, size: int, ok: bool) {
	str_blob := sections[".debug_str"]

	#partial switch form {
	case Dw_Form.strp:
		str_off := slice_to_type(data, u32) or_return
		str := strings.clone_from_cstring(cstring(raw_data(str_blob[str_off:])))

		return Attr_Data(str), size_of(str_off), true
	case Dw_Form.data2:
		val := slice_to_type(data, u16) or_return

		return Attr_Data(val), size_of(val), true
	case Dw_Form.sec_offset:
		val := slice_to_type(data, u32) or_return

		return Attr_Data(val), size_of(val), true
	case Dw_Form.flag_present:
		return Attr_Data(bool(true)), 0, true
	case Dw_Form.addr:
		addr := slice_to_type(data, u64) or_return

		return Attr_Data(addr), size_of(addr), true
	case Dw_Form.block1:
		length := slice_to_type(data, u8) or_return
		block := slice.clone(data[1:int(length)])

		return Attr_Data(block), size_of(length) + int(length), true
	case Dw_Form.data1:
		val := slice_to_type(data, u8) or_return

		return Attr_Data(val), size_of(val), true
	case Dw_Form.data4:
		val := slice_to_type(data, u32) or_return

		return Attr_Data(val), size_of(val), true
	case Dw_Form.udata:
		val, leb_size, err := varint.decode_uleb128(data)

		return Attr_Data(u64(val)), leb_size, true
	case Dw_Form.sdata:
		val, leb_size, err := varint.decode_ileb128(data)

		return Attr_Data(i64(val)), leb_size, true
	case Dw_Form.ref4:
		val := slice_to_type(data, u32) or_return

		return Attr_Data(val), size_of(val), true
	case Dw_Form.exprloc:
		expr_length, leb_size, err := varint.decode_uleb128(data)
		expr := slice.clone(data[leb_size:leb_size+int(expr_length)])

		return Attr_Data(expr), int(expr_length) + leb_size, true
	case: panic("TODO Can't handle (%d) %s yet!\n", form, form)
	}

	return
}

load_block_table :: proc(sections: ^map[string][]u8) -> ^Block {
	abbrev_blob := sections[".debug_abbrev"]

	abbrevs := make([dynamic]Abbrev_Unit)

	cu_idx := 0
	i := 0
	for i < len(abbrev_blob) {
		abbrev_code, leb_size_1, err_1 := varint.decode_uleb128(abbrev_blob[i:])
		if err_1 != nil {
			panic("Invalid abbrev code!\n")
		}
		i += leb_size_1

		if abbrev_code == 0 {
			cu_idx += 1
			continue
		}

		entry := Abbrev_Unit{}
		entry.id = u64(abbrev_code)
		entry.cu_idx = cu_idx

		entry_type, leb_size_2, err_2 := varint.decode_uleb128(abbrev_blob[i:])
		if err_2 != nil {
			panic("Invalid attr form!\n")
		}
		i += leb_size_2

		entry.type = Dw_Tag(entry_type)
		entry.has_children = abbrev_blob[i] > 0
		i += 1

		attrs_start := i
		for i < len(abbrev_blob) {
			attr_name, leb_size_1, err_1 := varint.decode_uleb128(abbrev_blob[i:])
			if err_1 != nil {
				panic("Invalid attr name!\n")
			}
			i += leb_size_1

			attr_form, leb_size_2, err_2 := varint.decode_uleb128(abbrev_blob[i:])
			if err_2 != nil {
				panic("Invalid attr form!\n")
			}
			i += leb_size_2

			if attr_name == 0 && attr_form == 0 {
				break
			}
		}

		entry.attrs_buf = abbrev_blob[attrs_start:i]
		append(&abbrevs, entry)
	}

	info_blob := sections[".debug_info"]

	MAX_BLOCK_STACK :: 30
	entry_stack := [MAX_BLOCK_STACK]^Block{}

	head_block := new(Block)
	head_block.type = Dw_Tag.program
	head_block.children = make([dynamic]^Block)
	entry_stack[0] = head_block

	cur_cu_idx := 0
	cur_blk_id := 1
	for i := 0; i < len(info_blob); {
		version_chunk, infok := slice_to_type(info_blob[i:], u32)
		if !infok {
			panic("Unable to read DWARF CU version!\n")
		}
		if version_chunk == 0xFFFFFFFF {
			panic("TODO debugger only supports 32 bit DWARF!\n")
		}

		cu_hdr, hdr_ok := slice_to_type(info_blob[i:], DWARF32_CU_Header)
		if !infok {
			panic("Unable to read DWARF CU version!\n")
		}
		if cu_hdr.version != 4 {
			panic("TODO debugger only supports DWARF 4, got %d!\n", cu_hdr.version)
		}
		i += size_of(cu_hdr)

		if cu_hdr.address_size != 8 {
			panic("TODO debugger only supports address size of 8!\n")
		}

		child_level := 1
		first_entry := true
		for first_entry || child_level > 1 {
			first_entry = false

			abbrev_id, leb_size_1, err_1 := varint.decode_uleb128(info_blob[i:])
			if err_1 != nil {
				panic("Invalid attr name!\n")
			}
			i += leb_size_1

			if abbrev_id == 0 {
				child_level -= 1
				continue
			}

			au : ^Abbrev_Unit = nil
			for cur_au := 0; cur_au < len(abbrevs); cur_au += 1 {
				tmp := abbrevs[cur_au]

				if (tmp.id == u64(abbrev_id)) && (tmp.cu_idx == cur_cu_idx) {
					au = &tmp
					break
				}
			}
			if au == nil {
				panic("Unable to find abbrev entry %d\n", abbrev_id)
			}

			blk := new(Block)
			blk.type = au.type
			blk.id = cur_blk_id
			blk.parent = entry_stack[child_level - 1]

			for j := 0; j < len(au.attrs_buf); {
				attr_name, leb_size_1, err_1 := varint.decode_uleb128(au.attrs_buf[j:])
				if err_1 != nil {
					panic("Invalid attr name!\n")
				}
				j += leb_size_1

				attr_form, leb_size_2, err_2 := varint.decode_uleb128(au.attrs_buf[j:])
				if err_2 != nil {
					panic("Invalid attr form!\n")
				}
				j += leb_size_2

				if attr_name == 0 && attr_form == 0 {
					break
				}

				data, skip_size, ok := parse_attr_data(sections, Dw_Form(attr_form), info_blob[i:])
				if !ok {
					panic("Invalid attr data!\n")
				}

				blk.attrs[Dw_At(attr_name)] = Attr_Entry{form = Dw_Form(attr_form), data = data}
				i += skip_size
			}

			append(&entry_stack[child_level - 1].children, blk)
			entry_stack[child_level] = blk

			if au.has_children {
				if child_level + 1 >= len(entry_stack) {
					panic("Popped the abbrev entry stack!\n")
				}

				child_level += 1
			}

			cur_blk_id += 1
		}
	}


	return head_block
}

print_sections_by_size :: proc(sections: ^map[string][]u8) {
	sort_entries_by_length(sections)
	for k, v in sections {
		size := len(v) / 1024

		str_buf := [4096]u8{}
		b := strings.builder_from_slice(str_buf[:])

		if size > 0 {
			fmt.sbprintf(&b, "%d KB", size)
		} else {
			fmt.sbprintf(&b, "%d  B", len(v))
		}

		fmt.printf("%s %s\n", strings.left_justify(k, 21, " "), strings.right_justify(strings.to_string(b), 6, " "))
	}
}

main :: proc() {
	if len(os.args) < 2 {
		panic("Please provide the debugger a program to debug!\n")
	}

	binary_blob, ok := os.read_entire_file_from_filename(os.args[1])
	if !ok {
		panic("Failed to load file: %s\n", os.args[1])
	}

	sections := load_elf(binary_blob)
//	print_sections_by_size(&sections)

	head := load_block_table(&sections)
	print_block_tree(head)
}
