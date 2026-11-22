#include "Disassembler.h"
#include <Zydis/Zydis.h>
#include <cstdio>
#include <cstring>

namespace analyser::disasm {

namespace {

FlowKind Classify(const ZydisDecodedInstruction& ins)
{
	switch (ins.meta.category) {
	case ZYDIS_CATEGORY_CALL: return FlowKind::Call;
	case ZYDIS_CATEGORY_RET: return FlowKind::Ret;
	case ZYDIS_CATEGORY_UNCOND_BR: return FlowKind::Jump;
	case ZYDIS_CATEGORY_COND_BR: return FlowKind::CondJump;
	default: return FlowKind::None;
	}
}

void MarkMaskRange(uint16_t& mask, uint8_t offset, uint8_t sizeBits, uint8_t instrLen)
{
	const uint8_t sizeBytes = sizeBits / 8;
	for (uint8_t b = 0; b < sizeBytes && (offset + b) < instrLen && (offset + b) < 15; ++b)
	{
		mask |= static_cast<uint16_t>(1u << (offset + b));
	}
}

bool IsStaticMemOperand(const ZydisDecodedOperand& op)
{
	return op.type == ZYDIS_OPERAND_TYPE_MEMORY &&
		op.mem.index == ZYDIS_REGISTER_NONE &&
		(op.mem.base == ZYDIS_REGISTER_NONE ||
		 op.mem.base == ZYDIS_REGISTER_RIP ||
		 op.mem.base == ZYDIS_REGISTER_EIP);
}

StaticAccessKind ClassifyStaticAccess(const ZydisDecodedInstruction& ins, const ZydisDecodedOperand& op, FlowKind flow)
{
	if (flow == FlowKind::Call)
	{
		return StaticAccessKind::CallSlot;
	}
	if (flow == FlowKind::Jump || flow == FlowKind::CondJump)
	{
		return StaticAccessKind::JumpSlot;
	}
	if (ins.mnemonic == ZYDIS_MNEMONIC_LEA || op.mem.type == ZYDIS_MEMOP_TYPE_AGEN)
	{
		return StaticAccessKind::Lea;
	}
	const bool r = (op.actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0;
	const bool w = (op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0;
	if (r && w)
	{
		return StaticAccessKind::ReadWrite;
	}
	if (w)
	{
		return StaticAccessKind::Write;
	}
	return StaticAccessKind::Read;
}

}

void Decode(const uint8_t* data, size_t size, uintptr_t runtimeAddress, size_t pointerSize,
			size_t maxLines, std::vector<InstructionLine>& out)
{
	out.clear();
	const bool is64 = pointerSize == 8;

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder,
		is64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
		is64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);

	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	size_t offset = 0;
	while (offset < size && out.size() < maxLines) {
		InstructionLine line;
		line.address = runtimeAddress + offset;

		ZydisDecodedInstruction ins;
		ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
		if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data + offset, size - offset, &ins, ops))) {
			char buf[256];
			if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter, &ins, ops,
					ins.operand_count_visible, buf, sizeof(buf), line.address, ZYAN_NULL)))
				line.text = buf;
			line.length = ins.length;
			line.valid = true;
			if (const char* mnemonic = ZydisMnemonicGetString(ins.mnemonic))
				line.mnemonic = mnemonic;
			line.flow = Classify(ins);

			// Inspect visible operands for branch targets and static memory references.
			bool hasRelOrStaticDisp = false;
			for (ZyanU8 i = 0; i < ins.operand_count_visible; ++i) {
				const auto& op = ops[i];
				if (i == 0 && line.flow != FlowKind::None && line.flow != FlowKind::Ret) {
					ZyanU64 target = 0;
					if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
						ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &op, line.address, &target))) {
						line.hasTarget = true;
						line.target = static_cast<uintptr_t>(target);
					} else if (IsStaticMemOperand(op) &&
						ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &op, line.address, &target))) {
						line.hasMemTarget = true;
						line.memTarget = static_cast<uintptr_t>(target);
					}
				}
				if (!line.hasStaticMem && IsStaticMemOperand(op)) {
					ZyanU64 memAddr = 0;
					if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &op, line.address, &memAddr))) {
						line.hasStaticMem = true;
						line.staticMemAddress = static_cast<uintptr_t>(memAddr);
						line.staticAccess = ClassifyStaticAccess(ins, op, line.flow);
						hasRelOrStaticDisp = true;
					}
				}
			}

			// Mask relocatable displacement bytes (RIP-relative, static disp32, or 32/64-bit displacements).
			if (ins.raw.disp.size >= 32 || (hasRelOrStaticDisp && ins.raw.disp.size > 0)) {
				MarkMaskRange(line.wildcardMask, ins.raw.disp.offset, ins.raw.disp.size, ins.length);
			}
			// Mask relative branch immediates (call/jmp/jcc) and pointer-sized immediates (x86/x64 addresses).
			for (int m = 0; m < 2; ++m) {
				const auto& imm = ins.raw.imm[m];
				if (imm.size == 0)
					continue;
				if (imm.is_relative || imm.size >= static_cast<ZyanU8>(pointerSize * 8)) {
					MarkMaskRange(line.wildcardMask, imm.offset, imm.size, ins.length);
				}
			}
		} else {
			line.length = 1;
			char buf[16];
			snprintf(buf, sizeof(buf), "db %02Xh", data[offset]);
			line.text = buf;
		}
		memcpy(line.bytes, data + offset, line.length);
		offset += line.length;
		out.push_back(std::move(line));
	}
}

}
