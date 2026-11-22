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
			if (line.flow != FlowKind::None && line.flow != FlowKind::Ret && ins.operand_count_visible > 0) {
				ZyanU64 target = 0;
				const auto& op = ops[0];
				if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
					ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &op, line.address, &target))) {
					line.hasTarget = true;
					line.target = static_cast<uintptr_t>(target);
				} else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.index == ZYDIS_REGISTER_NONE &&
					(op.mem.base == ZYDIS_REGISTER_NONE || op.mem.base == ZYDIS_REGISTER_RIP ||
					 op.mem.base == ZYDIS_REGISTER_EIP) &&
					ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &op, line.address, &target))) {
					line.hasMemTarget = true;
					line.memTarget = static_cast<uintptr_t>(target);
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
