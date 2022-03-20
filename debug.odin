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


Section_Header_Type :: enum u32 {
	null     = 0,
	progbits = 1,
	symtab   = 2,
	strtab   = 3,
	rela     = 4,
	hash     = 5,
	dyn      = 6,
	nobits   = 8,
	rel      = 9,
}

Section_Type :: enum u32 {
	null    = 0,
	load    = 1,
	dyn     = 2,
	interp  = 3,
	note    = 4,
	shlib   = 5,
	phdr    = 6,
	tls     = 7,
	gnu_eh_frame = 0x6474e550,
	gnu_stack = 0x6474e551,
	gnu_relro = 0x6474e552,
	gnu_property = 0x6474e553,
	lowproc = 0x70000000,
	hiproc  = 0x7FFFFFFF,
}

Dynamic_Type :: enum u64 {
	null         = 0,
	needed       = 1,
	plt_rel_size = 2,
	plt_got      = 3,
	hash         = 4,
	strtab       = 5,
	symtab       = 6,
	rela         = 7,
	rela_size    = 8,
	rela_entry   = 9,
	str_size     = 10,
	symbol_entry = 11,
	init         = 12,
	fini         = 13,
	so_name      = 14,
	rpath        = 15,
	symbolic     = 16,
	rel          = 17,
	rel_size     = 18,
	rel_entry    = 19,
	plt_rel      = 20,
	debug        = 21,
	text_rel     = 22,
	jump_rel     = 23,
	bind_now     = 24,
	init_array   = 25,
	init_array_size  = 26,
	fini_array       = 27,
	fini_array_size  = 28,
	gnu_hash         = 0x6FFFFEF5,
	version_symbol   = 0x6FFFFFF0,
	version_need     = 0x6FFFFFFE,
	version_need_num = 0x6FFFFFFF,
	lo_proc          = 0x70000000,
	hi_proc          = 0x7FFFFFFF,
}

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
	type: Section_Header_Type,
	flags: u64,
	addr: u64,
	offset: u64,
	size: u64,
	link: u32,
	info: u32,
	addr_align: u64,
	entry_size: u64,
}

ELF64_Program_Header :: struct #packed {
	type: Section_Type,
	flags: u32,
	offset: u64,
	virtual_addr: u64,
	physical_addr: u64,
	file_size: u64,
	mem_size: u64,
	align: u64,
}

ELF64_Dyn :: struct #packed {
	tag: Dynamic_Type,
	val: u64,
}

DWARF32_CU_Header :: struct {
	unit_type: Dw_Unit_Type,
	address_size: u8,
	abbrev_offset: u32,
}

DWARF32_V5_CU_Header :: struct #packed {
	unit_type: Dw_Unit_Type,
	address_size: u8,
	abbrev_offset: u32,
}

DWARF32_V4_CU_Header :: struct #packed {
	abbrev_offset: u32,
	address_size: u8,
}

DWARF_V4_Line_Header :: struct #packed {
	min_inst_length:  u8,
	max_ops_per_inst: u8,
	default_is_stmt:  u8,
	line_base:        i8,
	line_range:       u8,
	opcode_base:      u8,
}

DWARF_V3_Line_Header :: struct #packed {
	min_inst_length:  u8,
	default_is_stmt:  u8,
	line_base:        i8,
	line_range:       u8,
	opcode_base:      u8,
}

DWARF_Line_Header :: struct {
	min_inst_length:  u8,
	max_ops_per_inst: u8,
	default_is_stmt:  u8,
	line_base:        i8,
	line_range:       u8,
	opcode_base:      u8,
}

Line_Machine :: struct {
	address:         u64,
	op_idx:          u32,
	file_idx:        u32,
	line_num:        u32,
	col_num:         u32,
	is_stmt:        bool,
	basic_block:    bool,
	end_sequence:   bool,
	prologue_end:   bool,
	epilogue_end:   bool,
	epilogue_begin: bool,
	isa:             u32,
	discriminator:   u32,
}

Line_Table :: struct {
	op_buffer:       []u8,
	default_is_stmt: bool,
	line_base:         i8,
	line_range:        u8,
	opcode_base:       u8,

	lines: []Line_Machine,
}

Dw_LNS :: enum u8 {
	extended         = 0x0,
	copy             = 0x1,
	advance_pc       = 0x2,
	advance_line     = 0x3,
	set_file         = 0x4,
	set_column       = 0x5,
	negate_stmt      = 0x6,
	set_basic_block  = 0x7,
	const_add_pc     = 0x8,
	fixed_advance_pc = 0x9,
	set_prologue_end = 0xa,
}

Dw_Line :: enum u8 {
	end_sequence = 0x1,
	set_address = 0x2,
}

File_Unit :: struct {
	name:       string,
	dir_idx:       int,
}

Block :: struct {
	id: int,
	type: Dw_Tag,
	attrs: map[Dw_At]Attr_Entry,

	type_idx: int,
	abstract_idx: int,

	parent_idx: int,
	au_offset: int,
	cu_offset: int,
	children: [dynamic]int,
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

Dw_Unit_Type :: enum u8 {
	compile       = 0x01,
	type          = 0x02,
	partial       = 0x03,
	skeleton      = 0x04,
	split_compile = 0x05,
	split_type    = 0x06,
	lo_user       = 0x80,
	hi_user       = 0xFF,
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
	elf_hdr, rk := slice_to_type(binary_blob, ELF64_Header)
	if !rk {
		panic("Invalid ELF file!\n")
	}

	elf_magic := []u8{ 0x7f, 'E', 'L', 'F' }
	if mem.compare(elf_hdr.magic[:], elf_magic) != 0 {
		panic("Invalid ELF file!\n")
	}

	if elf_hdr.hdr_version != 1 {
		panic("Your ELF is stupid\n")
	}

	if elf_hdr.class != ELFCLASS64 ||
	   elf_hdr.endian != ELFDATA2LSB ||
	   elf_hdr.machine != EM_X86_64 {
		panic("TODO only supports x86_64!\n")
	}

	if elf_hdr.type == ET_CORE {
		panic("TODO add coredump support!\n")
	}

	if !(elf_hdr.type == ET_EXEC || elf_hdr.type == ET_DYN) {
		panic("ELF file is not executable!\n")
	}

	if elf_hdr.section_hdr_offset > u64(len(binary_blob)) {
		panic("Invalid section header offset!\n")
	}

	program_header_array_size := int(elf_hdr.program_hdr_num) * int(elf_hdr.program_hdr_entry_size)
	program_header_blob := binary_blob[int(elf_hdr.program_hdr_offset):int(elf_hdr.program_hdr_offset)+program_header_array_size]
	for i := 0; i < program_header_array_size; i += int(elf_hdr.program_hdr_entry_size) {
		prog_hdr, pok := slice_to_type(program_header_blob[i:], ELF64_Program_Header)
		if !pok {
			panic("Failed to get program header!\n")
		}

		if prog_hdr.type == Section_Type.interp {
			linker_path := binary_blob[prog_hdr.offset:prog_hdr.offset+prog_hdr.mem_size]
			fmt.printf("Using dynamic linker: %s\n", cstring(raw_data(linker_path)))
		}
	}

	str_table_hdr_idx := elf_hdr.section_hdr_offset + u64(elf_hdr.section_hdr_str_idx * elf_hdr.section_entry_size)
	if str_table_hdr_idx > u64(len(binary_blob)) {
		panic("Invalid str table header index!\n")
	}

	str_table_hdr, strk := slice_to_type(binary_blob[str_table_hdr_idx:], ELF64_Section_Header)
	if !strk {
		panic("Invalid ELF file!\n")
	}

	if str_table_hdr.type != Section_Header_Type.strtab {
		panic("Executable string table is borked!\n")
	}

	if str_table_hdr.offset > u64(len(binary_blob)) {
		panic("Invalid str table offset!\n")
	}

	section_header_array_size := int(elf_hdr.section_hdr_num) * int(elf_hdr.section_entry_size)
	section_header_blob := binary_blob[int(elf_hdr.section_hdr_offset):int(elf_hdr.section_hdr_offset)+section_header_array_size]
	sections := make(map[string][]u8)
	for i := 0; i < section_header_array_size; i += int(elf_hdr.section_entry_size) {
		section_hdr, sk := slice_to_type(section_header_blob[i:], ELF64_Section_Header)
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
		if section_hdr.type == Section_Header_Type.nobits || section_hdr.type == Section_Header_Type.null {
			sections[section_name] = nil
		} else {
			sections[section_name] = binary_blob[section_hdr.offset:section_hdr.offset+section_hdr.size]
		}
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

print_block_tree :: proc(tree: ^[]Block, node_idx: int = 0, depth: int = 0) {
	pad_buf := [?]u8{0..<32 = '\t',}
	if depth > len(pad_buf) {
		panic("Tree too deep!\n")
	}
	padding := pad_buf[len(pad_buf) - depth:]

	node := tree[node_idx]

	fmt.printf("%s%d | %s <%x>\n", padding, node.id, node.type, node.au_offset)
	for key, value in node.attrs {
/*
		if key == Dw_At.type {
			fmt.printf("%s - %s -- %d\n", padding, key, node.type_idx)
			continue
		} else if key == Dw_At.abstract_origin {
			fmt.printf("%s - %s -- %d\n", padding, key, node.abstract_idx)
			continue
		}
*/

		switch in value.data {
		case i64:
			fmt.printf("%s - %s -- %x\n", padding, key, value.data)
		case u64:
			fmt.printf("%s - %s -- %x\n", padding, key, value.data)
		case u32:
			fmt.printf("%s - %s -- %x\n", padding, key, value.data)
		case u16:
			fmt.printf("%s - %s -- %x\n", padding, key, value.data)
		case u8:
			fmt.printf("%s - %s -- %x\n", padding, key, value.data)
		case []u8:
			fmt.printf("%s - %s -- %x\n", padding, key, value.data)
		case bool:
			fmt.printf("%s - %s -- %t\n", padding, key, value.data)
		case string:
			fmt.printf("%s - %s -- %s\n", padding, key, value.data)
		}
	}

	for i := 0; i < len(node.children); i += 1 {
		print_block_tree(tree, node.children[i], depth + 1)
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

load_dynamic_libraries :: proc(sections: ^map[string][]u8) {
	dynamic_blob := sections[".dynamic"]
	dynstr_blob := sections[".dynstr"]

	for i := 0; i < len(dynamic_blob); i += size_of(ELF64_Dyn) {
		dyn_entry, ok := slice_to_type(dynamic_blob[i:], ELF64_Dyn)
		if !ok {
			panic("Unable to read ELF dynamic tag\n")
		}

		if dyn_entry.tag == Dynamic_Type.needed {
			section_name := cstring(raw_data(dynstr_blob[dyn_entry.val:]))
			fmt.printf("%s %s\n", dyn_entry.tag, section_name);
		} else {
			//fmt.printf("%s 0x%x\n", dyn_entry.tag, dyn_entry.val);
		}
	}
}

load_block_tree :: proc(sections: ^map[string][]u8) -> []Block {
	abbrev_blob := sections[".debug_abbrev"]

	abbrevs := make([dynamic]Abbrev_Unit)

	AU_ID_Lookup :: map[u64]int
	cu_au_table := make([dynamic]AU_ID_Lookup)

	lookup_1 := make(AU_ID_Lookup)
	append(&cu_au_table, lookup_1)

	cu_idx := 0
	cu_start := 0
	i := 0
	for i < len(abbrev_blob) {
		abbrev_code, leb_size_1, err_1 := varint.decode_uleb128(abbrev_blob[i:])
		if err_1 != nil {
			panic("Invalid abbrev code!\n")
		}
		i += leb_size_1

		if abbrev_code == 0 {
			cu_start = i
			cu_idx += 1

			new_lookup := make(AU_ID_Lookup)
			append(&cu_au_table, new_lookup)
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
		cu_au_table[cu_idx][entry.id] = len(abbrevs)
		append(&abbrevs, entry)
	}

	fmt.printf("File contains %d CUs\n", cu_idx)

	info_blob := sections[".debug_info"]

	MAX_BLOCK_STACK :: 30
	entry_stack := [MAX_BLOCK_STACK]int{}

	blocks := make([dynamic]Block)
	au_offset_lookup := make(map[u32]int)

	head_block := Block{}
	head_block.type = Dw_Tag.program
	head_block.children = make([dynamic]int)
	append(&blocks, head_block)
	entry_stack[0] = 0

	cur_cu_idx := 0
	cur_cu_offset := 0
	cur_blk_id := 1
	for i := 0; i < len(info_blob); {
		unit_length, linek := slice_to_type(info_blob[i:], u32)
		if !linek {
			panic("Unable to read DWARF Section version!\n")
		}
		if unit_length == 0xFFFFFFFF {
			panic("TODO debugger only supports 32 bit DWARF!\n")
		}
		i += size_of(unit_length)

		version, vk := slice_to_type(info_blob[i:], u16)
		if !vk {
			panic("Unable to read section version\n")
		}
		if !(version == 4 || version == 5) {
			panic("Block parser only supports DWARF 4 and 5, got %d!\n", version)
		}
		i += size_of(version)

		cu_hdr : DWARF32_CU_Header
		if version == 4 {
			tmp_hdr, vk := slice_to_type(info_blob[i:], DWARF32_V4_CU_Header)
			if !vk {
				panic("Unable to read v4 DWARF header\n")
			}

			cu_hdr.address_size = tmp_hdr.address_size
			cu_hdr.abbrev_offset = tmp_hdr.abbrev_offset

			i += size_of(tmp_hdr)
		} else if version == 5 {
			tmp_hdr, vk := slice_to_type(info_blob[i:], DWARF32_V5_CU_Header)
			if !vk {
				panic("Unable to read v5 DWARF header\n")
			}

			cu_hdr.unit_type = Dw_Unit_Type(tmp_hdr.unit_type)
			cu_hdr.address_size = tmp_hdr.address_size
			cu_hdr.abbrev_offset = tmp_hdr.abbrev_offset

			if cu_hdr.unit_type != .compile {
				panic("TODO only handles \"compile unit\", got a \"%s unit\"!\n", cu_hdr.unit_type)
			}

			i += size_of(tmp_hdr)
		}

		if cu_hdr.address_size != 8 {
			panic("TODO debugger only supports address size of 8, got %d!\n", cu_hdr.address_size)
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

			abbrev_idx, aok := cu_au_table[cur_cu_idx][u64(abbrev_id)]
			if !aok {
				panic("Unable to find abbrev entry %d\n", abbrev_id)
			}
			au := &abbrevs[abbrev_idx]

			blk := Block{}
			blk.type = au.type
			blk.id = cur_blk_id
			blk.parent_idx = entry_stack[child_level - 1]
			blk.au_offset = i - leb_size_1
			blk.cu_offset = cur_cu_offset

			au_offset_lookup[u32(blk.au_offset)] = cur_blk_id

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
			append(&blocks, blk)

			parent_idx := entry_stack[child_level - 1]
			append(&blocks[parent_idx].children, cur_blk_id)
			entry_stack[child_level] = cur_blk_id

			if au.has_children {
				if child_level + 1 >= len(entry_stack) {
					panic("Popped the abbrev entry stack!\n")
				}

				child_level += 1
			}

			cur_blk_id += 1
		}

		cur_cu_idx += 1
		cur_cu_offset = i
	}

/*
	tree := blocks[:]
	print_block_tree(&tree)
*/

	// precache type + abstract info
	for i := 0; i < len(blocks); i += 1 {
		b1 := &blocks[i]

		type_field, ok := b1.attrs[Dw_At.type]
		if ok {
			if type_field.form != Dw_Form.ref4 {
				panic("Can't handle type field with form: %s\n", type_field.form)
			}

			type_offset, tok := type_field.data.(u32)
			if !tok {
				panic("Unexpected data type! %s\n", type_field.data)
			}

			global_type_offset := u32(type_offset) + u32(b1.cu_offset)
			b2_id, tok2 := au_offset_lookup[global_type_offset]
			if !tok2 {
				panic("Unable to find offset for type! %s\n", global_type_offset)
			}
			b1.type_idx = b2_id
		}

		abstract_field, ok2 := b1.attrs[Dw_At.abstract_origin]
		if ok2 {
			if abstract_field.form != Dw_Form.ref4 {
				panic("Can't handle type field with form: %s\n", abstract_field.form)
			}

			abstract_offset, tok := abstract_field.data.(u32)
			if !tok {
				panic("Unexpected data type! %s\n", abstract_field.data)
			}

			global_abstract_offset := u32(abstract_offset) + u32(b1.cu_offset)
			b2_id, tok2 := au_offset_lookup[global_abstract_offset]
			if !tok2 {
				panic("Unable to find offset for abstract! 0x%x\n", global_abstract_offset)
			}
			b1.abstract_idx = b2_id
		}
	}

	return blocks[:]
}

print_line_machine :: proc(lm: ^Line_Machine) {
	fmt.printf("%d:%d:%d | %b %b | <%x>\n", lm.file_idx, lm.line_num, lm.col_num, u8(lm.prologue_end), u8(lm.epilogue_begin), lm.address)
}

print_line_table :: proc(lts: []Line_Table) {
	for i := 0; i < len(lts); i += 1 {
		lt := lts[i]
		for j := 0; j < len(lt.lines); j += 1 {
			print_line_machine(&lt.lines[j])
		}
	}
}

load_file_table :: proc(sections: ^map[string][]u8) -> ([]string, []File_Unit, []Line_Table) {
	line_blob := sections[".debug_line"]

	dir_table := make([dynamic]string)
	file_table := make([dynamic]File_Unit)
	line_tables := make([dynamic]Line_Table)

	append(&dir_table, "local")

	for i := 0; i < len(line_blob); {
		unit_length, linek := slice_to_type(line_blob[i:], u32)
		if !linek {
			panic("Unable to read DWARF Section version!\n")
		}
		if unit_length == 0xFFFFFFFF {
			panic("TODO debugger only supports 32 bit DWARF!\n")
		}
		i += size_of(unit_length)

		if unit_length == 0 {
			continue
		}

		version, vk := slice_to_type(line_blob[i:], u16)
		if !vk {
			panic("Unable to read section version\n")
		}
		if !(version == 3 || version == 4) {
			panic("TODO This code supports DWARF 3 and 4, got %d\n", version)
		}
		i += size_of(version)

		header_length, hdrk := slice_to_type(line_blob[i:], u32)
		if !hdrk {
			panic("Unable to read section header length\n")
		}

		// This looks squirrely, just prep for eventually handling DWARF64
		header_length_size := size_of(u32)
		i += header_length_size

		line_hdr : DWARF_Line_Header
		if version == 3 {
			tmp_line_hdr, hdrk := slice_to_type(line_blob[i:], DWARF_V3_Line_Header)
			if !hdrk {
				panic("Unable to read section header\n")
			}

			line_hdr.min_inst_length  = tmp_line_hdr.min_inst_length;
			line_hdr.default_is_stmt  = tmp_line_hdr.default_is_stmt;
			line_hdr.line_base 	      = tmp_line_hdr.line_base;
			line_hdr.line_range 	  = tmp_line_hdr.line_range;
			line_hdr.opcode_base 	  = tmp_line_hdr.opcode_base;

			i += size_of(tmp_line_hdr)

		} else if version == 4 {
			tmp_line_hdr, hdrk := slice_to_type(line_blob[i:], DWARF_V4_Line_Header)
			if !hdrk {
				panic("Unable to read section header\n")
			}

			line_hdr.min_inst_length  = tmp_line_hdr.min_inst_length;
			line_hdr.max_ops_per_inst = tmp_line_hdr.max_ops_per_inst;
			line_hdr.default_is_stmt  = tmp_line_hdr.default_is_stmt;
			line_hdr.line_base 	      = tmp_line_hdr.line_base;
			line_hdr.line_range 	  = tmp_line_hdr.line_range;
			line_hdr.opcode_base 	  = tmp_line_hdr.opcode_base;

			i += size_of(tmp_line_hdr)
		}

		//print_line_header(line_hdr)

		if line_hdr.opcode_base != 13 {
			panic("Can't handle weird number of line ops / extensions! %d\n", line_hdr.opcode_base)
		}

		// WTF?
		opcode_table_len := line_hdr.opcode_base - 1
		i += int(opcode_table_len)
		for {
			//TODO(cloin): Should this be capped at PATH_MAX?
			cstr_dir_name := cstring(raw_data(line_blob[i:]))

			i += len(cstr_dir_name) + 1
			if len(cstr_dir_name) == 0 {
				break
			}

			dir_name := strings.clone_from_cstring(cstr_dir_name)
			append(&dir_table, dir_name)
		}

		for {
			//TODO(cloin): Should this be capped at PATH_MAX?
			cstr_file_name := cstring(raw_data(line_blob[i:]))

			i += len(cstr_file_name) + 1
			if len(cstr_file_name) == 0 {
				break
			}

			dir_idx, leb_size_1, err_1 := varint.decode_uleb128(line_blob[i:])
			if err_1 != nil {
				panic("Unable to read dir idx!\n")
			}
			i += leb_size_1

			last_modified, leb_size_2, err_2 := varint.decode_uleb128(line_blob[i:])
			if err_2 != nil {
				panic("Unable to read last modified!\n")
			}
			i += leb_size_2

			file_size, leb_size_3, err_3 := varint.decode_uleb128(line_blob[i:])
			if err_3 != nil {
				panic("Unable to read file size!\n")
			}
			i += leb_size_3


			file_name := strings.clone_from_cstring(cstr_file_name)
			fu := File_Unit{name = file_name, dir_idx = int(dir_idx)}
			append(&file_table, fu)
		}

		full_cu_size  := unit_length + size_of(unit_length)
		hdr_size := size_of(unit_length) + size_of(version) + int(header_length) + int(header_length_size)
		rem_size := int(full_cu_size) - hdr_size

		lt := Line_Table{}
		lt.op_buffer = line_blob[i:i+rem_size]
		lt.opcode_base = line_hdr.opcode_base
		lt.line_base   = line_hdr.line_base
		lt.line_range  = line_hdr.line_range

		append(&line_tables, lt)
		i += rem_size
	}

	for i := 0; i < len(line_tables); i += 1 {
		line_table := &line_tables[i]

		lm_state := Line_Machine{}
		lm_state.file_idx = 1
		lm_state.line_num = 1
		lm_state.is_stmt = line_table.default_is_stmt

		lines := make([dynamic]Line_Machine)

		for j := 0; j < len(line_table.op_buffer); {
			op_byte := line_table.op_buffer[j]

			j += 1

			if op_byte >= line_table.opcode_base {
				real_op := op_byte - line_table.opcode_base

				line_inc := int(line_table.line_base + i8(real_op % line_table.line_range))
				addr_inc := int(real_op / line_table.line_range)

				lm_state.line_num = u32(int(lm_state.line_num) + line_inc)
				lm_state.address  = u64(int(lm_state.address) + addr_inc)

				append(&lines, lm_state)

				lm_state.discriminator  = 0
				lm_state.basic_block    = false
				lm_state.prologue_end   = false
				lm_state.epilogue_begin = false

				continue
			}

			op := Dw_LNS(op_byte)
			if op == .extended {
				j += 1

				tmp := line_table.op_buffer[j]
				real_op := Dw_Line(tmp)

				#partial switch real_op {
				case .end_sequence:
					lm_state.end_sequence = true
					append(&lines, lm_state)
				case .set_address:
					address := slice_to_type(line_table.op_buffer[j:], u64)
					lm_state.address = address

					j += size_of(address)
				case:
					panic("Unsupported special op %d!\n", tmp)
				}

				j += 1
				continue
			}

			#partial switch op {
			case .copy:
				append(&lines, lm_state)

				lm_state.discriminator  = 0
				lm_state.basic_block    = false
				lm_state.prologue_end   = false
				lm_state.epilogue_begin = false
			case .advance_pc:
				addr_inc, leb_size, err := varint.decode_uleb128(line_table.op_buffer[j:])
				if err != nil {
					panic("Invalid file idx!\n")
				}
				lm_state.address = lm_state.address + u64(addr_inc)

				j += leb_size
			case .advance_line:
				line_inc, leb_size, err := varint.decode_ileb128(line_table.op_buffer[j:])
				if err != nil {
					panic("Invalid line increment!\n")
				}
				lm_state.line_num = u32(int(lm_state.line_num) + int(line_inc))

				j += leb_size
			case .set_file:
				file_idx, leb_size, err := varint.decode_uleb128(line_table.op_buffer[j:])
				if err != nil {
					panic("Invalid file idx!\n")
				}
				lm_state.file_idx = u32(file_idx)

				j += leb_size
			case .set_column:
				col_num, leb_size, err := varint.decode_uleb128(line_table.op_buffer[j:])
				if err != nil {
					panic("Invalid column number!\n")
				}
				lm_state.col_num = u32(col_num)

				j += leb_size
			case .negate_stmt:
				lm_state.is_stmt = !lm_state.is_stmt
			case .set_basic_block:
				lm_state.basic_block = true
			case .const_add_pc:
				addr_inc := (255 - line_table.opcode_base) / line_table.line_range
				lm_state.address += u64(addr_inc)
			case .fixed_advance_pc:
				advance := slice_to_type(line_table.op_buffer[j:], u16)
				lm_state.address += u64(advance)

				j += size_of(advance)
			case .set_prologue_end:
				lm_state.prologue_end = true
			case:
				panic("Unsupported op %d\n", op_byte)
			}
		}

		line_table.lines = lines[:]
	}

	return dir_table[:], file_table[:], line_tables[:]
}

print_file_table :: proc(dirs: []string, files: []File_Unit) {
	for i := 0; i < len(files); i += 1 {
		file := files[i]
		fmt.printf("%d | %s/%s\n", i, dirs[file.dir_idx], file.name)
	}
}

print_line_header :: proc(hdr: DWARF_Line_Header) {
	fmt.printf("min inst length:  %d\n", hdr.min_inst_length)
	fmt.printf("default is stmt:  %d\n", hdr.default_is_stmt)
	fmt.printf("line base:        %d\n", hdr.line_base)
	fmt.printf("line range:       %d\n", hdr.line_range)
	fmt.printf("opcode base:      %d\n", hdr.opcode_base)
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
	load_dynamic_libraries(&sections)


	tree := load_block_tree(&sections)
//	print_block_tree(&tree)

	dir_table, file_table, line_table := load_file_table(&sections)
//	print_file_table(dir_table, file_table)
//	print_line_table(line_table)
}
