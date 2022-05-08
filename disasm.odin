package peel

import "core:fmt"

Disasm_Register :: enum {
	rax,
	rcx,
	rdx,
	rbx,
	rsp,
	rbp,
	rsi,
	rdi,
	r8,
	r9,
	r10,
	r11,
	r12,
	r13,
	r14,
	r15,
}

Disasm_Instruction_Type :: enum {
	add,
	or,
	and,
	sub,
	sbb,
	xor,
	cmp,
	mov,
}

Disasm_Data_Type :: enum {
	byte,
	word,
	dword,
	qword,
	pbyte,
	pword,
	pdword,
	pqword,
	sse_ss,
	sse_ps,
	sse_pd,
	xmmword,
}

Disasm_Mod :: enum {
	indirect = 0,
	indirect_disp8  = 1,
	indirect_disp32 = 2,
	direct   = 3,
}

Disasm_Mem :: struct {
	base: u8,
	index: u8,
	scale: u8,
	disp: i32,
}

Operand_Return :: union {
	Disasm_Register,
	Disasm_Mem,
}

Disasm_Operand_Type :: enum {
	gpr,
	xmm,
	mem,
	rip,
	imm,
	offset,
	abs64,
}

Disasm_Reg_Return :: struct {
	type: Disasm_Operand_Type,
	data: Operand_Return,
}

Byte_Reader :: struct {
	s: []u8,
	i: i64,
}

decode_modrmrx :: proc(byte: u8) -> (mod: u8, rx: u8, rm: u8) {
	mod = byte >> 6
	rx  = (byte << 5) >> 5
	rm  = (byte << 2) >> 5
	return
}

init_byte_reader :: proc(bytecode: []u8) -> Byte_Reader {
	return Byte_Reader{s = bytecode, i = 0}
}

_read_data :: proc(br: ^Byte_Reader, $T: typeid) -> (T, bool) #optional_ok {
	if br.i >= i64(len(br.s)) {
		return {}, false
	}

	ret := slice_to_type(br.s[br.i:], T)
	br.i += size_of(T)

	return ret, true
}

parse_memory_op :: proc(rdr: ^Byte_Reader, mod: u8, rm: u8, rex: u8) -> (reg_ret: Disasm_Reg_Return, ok: bool) {
	reg := Disasm_Register(rm)
	dmod := Disasm_Mod(mod)

	if dmod == .direct {
		val := u8(((rex & 1) > 0) ? 8 : 0) | rm
		reg_ret = Disasm_Reg_Return{type = .gpr, data = Disasm_Register(val)}
		return reg_ret, true
	}

	if reg == .rsp {
		sib := _read_data(rdr, u8) or_return
		scale, index, base := decode_modrmrx(sib)

		base_reg  := (Disasm_Register(base)  != .rbp) ? ((rex & 1 > 0) ? 8 : 0) | base : 0
		index_reg := (Disasm_Register(index) != .rsp) ? ((rex & 2 > 0) ? 8 : 0) | index : 0

		if mod == 0 && Disasm_Register(base) == .rbp {
			dmod = .indirect_disp32
		}

		mem := Disasm_Mem{base = base_reg, index = index_reg, scale = scale, disp = 0}
		reg_ret = Disasm_Reg_Return{type = .mem, data = mem}
	} else {
		return {}, false
	}

/*
	if dmod == .indirect_disp8 {
		disp := _read_data(rdr, u8)
		#partial switch v in reg_ret.data {
		case Disasm_Mem: v.disp = i32(disp)
		}
	} else if dmod == .indirect_disp32 {
		disp := _read_data(rdr, u32)
		reg_ret.data.disp = disp
	}
*/

	return reg_ret, true
}

disasm_x64_inst :: proc(rdr: ^Byte_Reader) -> (bool) {
	rex : u8 = 0
	addr_16 := false
	rep     := false
	repne   := false

	op : u8
	for {
		op = _read_data(rdr, u8) or_return

		if (op & 0xF0) == 0x40 { rex = op }
		else if (op == 0x66) { addr_16 = true }
		else { break }
	}

	fmt.printf("0x%x | 0b%b\n", op, op)

	// pretends this is x64 bit only
	switch (op & 0xFC) {
	case 0x50: fallthrough
	case 0x54:
		hi_bits := ((rex & 1) > 0) ? 8 : 0
		fmt.printf("push %s\n", Disasm_Register(u8(hi_bits) | op - 0x50))
	case 0x88:
		op_type : Disasm_Instruction_Type
		switch (op & 0xFC) {
		case 0x00: op_type = .add
		case 0x08: op_type = .or
		case 0x18: op_type = .sbb
		case 0x28: op_type = .sub
		case 0x30: op_type = .xor
		case 0x38: op_type = .cmp
		case 0x88: op_type = .mov
		}

		width : Disasm_Data_Type
		if (op & 1) > 0 {
			if (rex & 8) > 0 { width = .qword }
			else if addr_16 { width = .word }
			else { width = .dword }
		} else {
			width = .byte
		}

		modrm_byte := _read_data(rdr, u8) or_return
		mod, rm, rx := decode_modrmrx(modrm_byte)

		direction := (op & 2) > 0
		hi_bits := ((rex & 4) > 0) ? 8 : 0
		reg := Disasm_Register(u8(hi_bits) | rx)

		imm := parse_memory_op(rdr, mod, rm, rex) or_return

		if direction {
			fmt.printf("%s %s, %s\n", op_type, reg, imm.data)
		} else {
			fmt.printf("%s %s, %s\n", op_type, imm.data, reg)
		}
	case 0x80:
		width : Disasm_Data_Type
		if (op & 1) > 0 {
			if (rex & 8) > 0 { width = .qword }
			else if addr_16 { width = .word }
			else { width = .dword }
		} else {
			width = .byte
		}

		modrm_byte := _read_data(rdr, u8) or_return
		mod, rm, rx := decode_modrmrx(modrm_byte)

		op_type : Disasm_Instruction_Type
		switch (rx) {
		case 0: op_type = .add
		case 1: op_type = .or
		case 4: op_type = .and
		case 5: op_type = .sub
		case 6: op_type = .xor
		case 7: op_type = .cmp
		case: panic("parse fail!\n")
		}

		reg_ret := parse_memory_op(rdr, mod, rm, rex) or_return
		if (op & 2) > 0 || width == .byte {
			imm := _read_data(rdr, u8) or_return
			fmt.printf("%s %s, 0x%x\n", op_type, reg_ret.data, imm)
		} else {
			imm := _read_data(rdr, u32) or_return
			fmt.printf("%s %s, 0x%x\n", op_type, reg_ret.data, imm)
		}
	case:
		panic("at the disco! 0x%x\n", op & 0xFC)
	}

	return true
}

disasm_x64_bytecode :: proc(bytecode: []u8) {
	rdr := init_byte_reader(bytecode)
	fmt.printf("%x\n", bytecode[:20])
	for {
		disasm_x64_inst(&rdr)
	}
}
