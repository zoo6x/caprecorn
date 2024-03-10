-- Unicorn and Capstone interfaces
local M = {}

-- Dependencies: Unicorn and Capstone
local unicorn = require("unicorn")
local unicorn_const = require("unicorn.unicorn_const")
local x86_const = require("unicorn.x86_const")
local arm_const = require("unicorn.arm_const")
local aarch64_const = require("unicorn.arm64_const")

local capstone = require("capstone")

M.unicorn = unicorn
M.unicorn_const = unicorn_const

M.capstone = capstone

local arch = require("arch")
M.arch = arch.arch

local arch_params = {
  [M.arch.X86_16] = {
    unicorn_arch = unicorn_const.UC_ARCH_X86,
    unicorn_mode = unicorn_const.UC_MODE_16,
    capstone_arch = capstone.CS_ARCH_X86,
    capstone_mode = capstone.CS_MODE_16,
  },
  [M.arch.X86_32] = {
    unicorn_arch = unicorn_const.UC_ARCH_X86,
    unicorn_mode = unicorn_const.UC_MODE_32,
    capstone_arch = capstone.CS_ARCH_X86,
    capstone_mode = capstone.CS_MODE_32,
  },
  [M.arch.X86_64] = {
    unicorn_arch = unicorn_const.UC_ARCH_X86,
    unicorn_mode = unicorn_const.UC_MODE_64,
    capstone_arch = capstone.CS_ARCH_X86,
    capstone_mode = capstone.CS_MODE_64,
  },
  [M.arch.ARM] = {
    unicorn_arch = unicorn_const.UC_ARCH_ARM,
    unicorn_mode = unicorn_const.UC_MODE_ARM,
    capstone_arch = capstone.CS_ARCH_ARM,
    capstone_mode = capstone.CS_MODE_ARM,
  },
  [M.arch.ARM_V6] = {
    unicorn_arch = unicorn_const.UC_ARCH_ARM,
    unicorn_mode = unicorn_const.UC_MODE_ARM + unicorn_const.UC_MODE_THUMB,
    capstone_arch = capstone.CS_ARCH_ARM,
    capstone_mode = capstone.CS_MODE_ARM + capstone.CS_MODE_THUMB,
  },
  [M.arch.ARM_V7] = {
    unicorn_arch = unicorn_const.UC_ARCH_ARM,
    unicorn_mode = unicorn_const.UC_MODE_ARM + unicorn_const.UC_MODE_THUMB,
    capstone_arch = capstone.CS_ARCH_ARM,
    capstone_mode = capstone.CS_MODE_ARM + capstone.CS_MODE_THUMB,
  },
  [M.arch.ARM_V8] = {
    unicorn_arch = unicorn_const.UC_ARCH_ARM,
    unicorn_mode = unicorn_const.UC_MODE_ARM + unicorn_const.UC_MODE_THUMB + unicorn_const.UC_MODE_V8,
    capstone_arch = capstone.CS_ARCH_ARM,
    capstone_mode = capstone.CS_MODE_ARM + capstone.CS_MODE_THUMB + unicorn_const.UC_MODE_V8,
  },

  [M.arch.AARCH64] = {
    unicorn_arch = unicorn_const.UC_ARCH_ARM64,
    unicorn_mode = unicorn_const.UC_MODE_ARM,
    capstone_arch = capstone.CS_ARCH_ARM64,
    capstone_mode = capstone.CS_MODE_ARM,
  },
}

--TODO: Should be architecture-specific
local x86_capstone_to_unicorn_reg_map = {
	[capstone.X86_REG_AH] = x86_const.UC_X86_REG_AH,
  [capstone.X86_REG_AL] = x86_const.UC_X86_REG_AL,
  [capstone.X86_REG_AX] = x86_const.UC_X86_REG_AX,
  [capstone.X86_REG_BH] = x86_const.UC_X86_REG_BH,
  [capstone.X86_REG_BL] = x86_const.UC_X86_REG_BL,
	[capstone.X86_REG_BP] = x86_const.UC_X86_REG_BP,
  [capstone.X86_REG_BPL] = x86_const.UC_X86_REG_BPL,
  [capstone.X86_REG_BX] = x86_const.UC_X86_REG_BX,
  [capstone.X86_REG_CH] = x86_const.UC_X86_REG_CH,
  [capstone.X86_REG_CL] = x86_const.UC_X86_REG_CL,
	[capstone.X86_REG_CS] = x86_const.UC_X86_REG_CS,
  [capstone.X86_REG_CX] = x86_const.UC_X86_REG_CX,
  [capstone.X86_REG_DH] = x86_const.UC_X86_REG_DH,
  [capstone.X86_REG_DI] = x86_const.UC_X86_REG_DI,
  [capstone.X86_REG_DIL] = x86_const.UC_X86_REG_DIL,
	[capstone.X86_REG_DL] = x86_const.UC_X86_REG_DL,
  [capstone.X86_REG_DS] = x86_const.UC_X86_REG_DS,
  [capstone.X86_REG_DX] = x86_const.UC_X86_REG_DX,
  [capstone.X86_REG_EAX] = x86_const.UC_X86_REG_EAX,
  [capstone.X86_REG_EBP] = x86_const.UC_X86_REG_EBP,
	[capstone.X86_REG_EBX] = x86_const.UC_X86_REG_EBX,
  [capstone.X86_REG_ECX] = x86_const.UC_X86_REG_ECX,
  [capstone.X86_REG_EDI] = x86_const.UC_X86_REG_EDI,
  [capstone.X86_REG_EDX] = x86_const.UC_X86_REG_EDX,
  [capstone.X86_REG_EFLAGS] = x86_const.UC_X86_REG_EFLAGS,
	[capstone.X86_REG_EIP] = x86_const.UC_X86_REG_EIP,
  --TODO: Handle EIZ pseudo-register somehow, if needed
  --Check when it appears in disassembly or details
  --[capstone.X86_REG_EIZ] = x86_const.UC_X86_REG_EIZ,
  [capstone.X86_REG_ES] = x86_const.UC_X86_REG_ES,
  [capstone.X86_REG_ESI] = x86_const.UC_X86_REG_ESI,
  [capstone.X86_REG_ESP] = x86_const.UC_X86_REG_ESP,
	[capstone.X86_REG_FPSW] = x86_const.UC_X86_REG_FPSW,
  [capstone.X86_REG_FS] = x86_const.UC_X86_REG_FS,
  [capstone.X86_REG_GS] = x86_const.UC_X86_REG_GS,
  [capstone.X86_REG_IP] = x86_const.UC_X86_REG_IP,
  [capstone.X86_REG_RAX] = x86_const.UC_X86_REG_RAX,
	[capstone.X86_REG_RBP] = x86_const.UC_X86_REG_RBP,
  [capstone.X86_REG_RBX] = x86_const.UC_X86_REG_RBX,
  [capstone.X86_REG_RCX] = x86_const.UC_X86_REG_RCX,
  [capstone.X86_REG_RDI] = x86_const.UC_X86_REG_RDI,
  [capstone.X86_REG_RDX] = x86_const.UC_X86_REG_RDX,
	[capstone.X86_REG_RIP] = x86_const.UC_X86_REG_RIP,
  --TODO: Same as EIZ
  --[capstone.X86_REG_RIZ] = x86_const.UC_X86_REG_RIZ,
  [capstone.X86_REG_RSI] = x86_const.UC_X86_REG_RSI,
  [capstone.X86_REG_RSP] = x86_const.UC_X86_REG_RSP,
  [capstone.X86_REG_SI] = x86_const.UC_X86_REG_SI,
	[capstone.X86_REG_SIL] = x86_const.UC_X86_REG_SIL,
  [capstone.X86_REG_SP] = x86_const.UC_X86_REG_SP,
  [capstone.X86_REG_SPL] = x86_const.UC_X86_REG_SPL,
  [capstone.X86_REG_SS] = x86_const.UC_X86_REG_SS,
  [capstone.X86_REG_CR0] = x86_const.UC_X86_REG_CR0,
	[capstone.X86_REG_CR1] = x86_const.UC_X86_REG_CR1,
  [capstone.X86_REG_CR2] = x86_const.UC_X86_REG_CR2,
  [capstone.X86_REG_CR3] = x86_const.UC_X86_REG_CR3,
  [capstone.X86_REG_CR4] = x86_const.UC_X86_REG_CR4,
  --[capstone.X86_REG_CR5] = x86_const.UC_X86_REG_CR5,
	--[capstone.X86_REG_CR6] = x86_const.UC_X86_REG_CR6,
  --[capstone.X86_REG_CR7] = x86_const.UC_X86_REG_CR7,
  [capstone.X86_REG_CR8] = x86_const.UC_X86_REG_CR8,
  --[capstone.X86_REG_CR9] = x86_const.UC_X86_REG_CR9,
  --[capstone.X86_REG_CR10] = x86_const.UC_X86_REG_CR10,
	--[capstone.X86_REG_CR11] = x86_const.UC_X86_REG_CR11,
  --[capstone.X86_REG_CR12] = x86_const.UC_X86_REG_CR12,
  --[capstone.X86_REG_CR13] = x86_const.UC_X86_REG_CR13,
  --[capstone.X86_REG_CR14] = x86_const.UC_X86_REG_CR14,
  --[capstone.X86_REG_CR15] = x86_const.UC_X86_REG_CR15,
	[capstone.X86_REG_DR0] = x86_const.UC_X86_REG_DR0,
  [capstone.X86_REG_DR1] = x86_const.UC_X86_REG_DR1,
  [capstone.X86_REG_DR2] = x86_const.UC_X86_REG_DR2,
  [capstone.X86_REG_DR3] = x86_const.UC_X86_REG_DR3,
  [capstone.X86_REG_DR4] = x86_const.UC_X86_REG_DR4,
	[capstone.X86_REG_DR5] = x86_const.UC_X86_REG_DR5,
  [capstone.X86_REG_DR6] = x86_const.UC_X86_REG_DR6,
  [capstone.X86_REG_DR7] = x86_const.UC_X86_REG_DR7,
  --[capstone.X86_REG_DR8] = x86_const.UC_X86_REG_DR8,
  --[capstone.X86_REG_DR9] = x86_const.UC_X86_REG_DR9,
	--[capstone.X86_REG_DR10] = x86_const.UC_X86_REG_DR10,
  --[capstone.X86_REG_DR11] = x86_const.UC_X86_REG_DR11,
  --[capstone.X86_REG_DR12] = x86_const.UC_X86_REG_DR12,
  --[capstone.X86_REG_DR13] = x86_const.UC_X86_REG_DR13,
  --[capstone.X86_REG_DR14] = x86_const.UC_X86_REG_DR14,
	--[capstone.X86_REG_DR15] = x86_const.UC_X86_REG_DR15,
  [capstone.X86_REG_FP0] = x86_const.UC_X86_REG_FP0,
  [capstone.X86_REG_FP1] = x86_const.UC_X86_REG_FP1,
  [capstone.X86_REG_FP2] = x86_const.UC_X86_REG_FP2,
  [capstone.X86_REG_FP3] = x86_const.UC_X86_REG_FP3,
	[capstone.X86_REG_FP4] = x86_const.UC_X86_REG_FP4,
  [capstone.X86_REG_FP5] = x86_const.UC_X86_REG_FP5,
  [capstone.X86_REG_FP6] = x86_const.UC_X86_REG_FP6,
  [capstone.X86_REG_FP7] = x86_const.UC_X86_REG_FP7,
	[capstone.X86_REG_K0] = x86_const.UC_X86_REG_K0,
  [capstone.X86_REG_K1] = x86_const.UC_X86_REG_K1,
  [capstone.X86_REG_K2] = x86_const.UC_X86_REG_K2,
  [capstone.X86_REG_K3] = x86_const.UC_X86_REG_K3,
  [capstone.X86_REG_K4] = x86_const.UC_X86_REG_K4,
	[capstone.X86_REG_K5] = x86_const.UC_X86_REG_K5,
  [capstone.X86_REG_K6] = x86_const.UC_X86_REG_K6,
  [capstone.X86_REG_K7] = x86_const.UC_X86_REG_K7,
  [capstone.X86_REG_MM0] = x86_const.UC_X86_REG_MM0,
  [capstone.X86_REG_MM1] = x86_const.UC_X86_REG_MM1,
	[capstone.X86_REG_MM2] = x86_const.UC_X86_REG_MM2,
  [capstone.X86_REG_MM3] = x86_const.UC_X86_REG_MM3,
  [capstone.X86_REG_MM4] = x86_const.UC_X86_REG_MM4,
  [capstone.X86_REG_MM5] = x86_const.UC_X86_REG_MM5,
  [capstone.X86_REG_MM6] = x86_const.UC_X86_REG_MM6,
	[capstone.X86_REG_MM7] = x86_const.UC_X86_REG_MM7,
  [capstone.X86_REG_R8] = x86_const.UC_X86_REG_R8,
  [capstone.X86_REG_R9] = x86_const.UC_X86_REG_R9,
  [capstone.X86_REG_R10] = x86_const.UC_X86_REG_R10,
  [capstone.X86_REG_R11] = x86_const.UC_X86_REG_R11,
	[capstone.X86_REG_R12] = x86_const.UC_X86_REG_R12,
  [capstone.X86_REG_R13] = x86_const.UC_X86_REG_R13,
  [capstone.X86_REG_R14] = x86_const.UC_X86_REG_R14,
  [capstone.X86_REG_R15] = x86_const.UC_X86_REG_R15,
	[capstone.X86_REG_ST0] = x86_const.UC_X86_REG_ST0,
  [capstone.X86_REG_ST1] = x86_const.UC_X86_REG_ST1,
  [capstone.X86_REG_ST2] = x86_const.UC_X86_REG_ST2,
  [capstone.X86_REG_ST3] = x86_const.UC_X86_REG_ST3,
	[capstone.X86_REG_ST4] = x86_const.UC_X86_REG_ST4,
  [capstone.X86_REG_ST5] = x86_const.UC_X86_REG_ST5,
  [capstone.X86_REG_ST6] = x86_const.UC_X86_REG_ST6,
  [capstone.X86_REG_ST7] = x86_const.UC_X86_REG_ST7,
	[capstone.X86_REG_XMM0] = x86_const.UC_X86_REG_XMM0,
  [capstone.X86_REG_XMM1] = x86_const.UC_X86_REG_XMM1,
  [capstone.X86_REG_XMM2] = x86_const.UC_X86_REG_XMM2,
  [capstone.X86_REG_XMM3] = x86_const.UC_X86_REG_XMM3,
  [capstone.X86_REG_XMM4] = x86_const.UC_X86_REG_XMM4,
	[capstone.X86_REG_XMM5] = x86_const.UC_X86_REG_XMM5,
  [capstone.X86_REG_XMM6] = x86_const.UC_X86_REG_XMM6,
  [capstone.X86_REG_XMM7] = x86_const.UC_X86_REG_XMM7,
  [capstone.X86_REG_XMM8] = x86_const.UC_X86_REG_XMM8,
  [capstone.X86_REG_XMM9] = x86_const.UC_X86_REG_XMM9,
	[capstone.X86_REG_XMM10] = x86_const.UC_X86_REG_XMM10,
  [capstone.X86_REG_XMM11] = x86_const.UC_X86_REG_XMM11,
  [capstone.X86_REG_XMM12] = x86_const.UC_X86_REG_XMM12,
  [capstone.X86_REG_XMM13] = x86_const.UC_X86_REG_XMM13,
  [capstone.X86_REG_XMM14] = x86_const.UC_X86_REG_XMM14,
	[capstone.X86_REG_XMM15] = x86_const.UC_X86_REG_XMM15,
  [capstone.X86_REG_XMM16] = x86_const.UC_X86_REG_XMM16,
  [capstone.X86_REG_XMM17] = x86_const.UC_X86_REG_XMM17,
  [capstone.X86_REG_XMM18] = x86_const.UC_X86_REG_XMM18,
  [capstone.X86_REG_XMM19] = x86_const.UC_X86_REG_XMM19,
	[capstone.X86_REG_XMM20] = x86_const.UC_X86_REG_XMM20,
  [capstone.X86_REG_XMM21] = x86_const.UC_X86_REG_XMM21,
  [capstone.X86_REG_XMM22] = x86_const.UC_X86_REG_XMM22,
  [capstone.X86_REG_XMM23] = x86_const.UC_X86_REG_XMM23,
  [capstone.X86_REG_XMM24] = x86_const.UC_X86_REG_XMM24,
	[capstone.X86_REG_XMM25] = x86_const.UC_X86_REG_XMM25,
  [capstone.X86_REG_XMM26] = x86_const.UC_X86_REG_XMM26,
  [capstone.X86_REG_XMM27] = x86_const.UC_X86_REG_XMM27,
  [capstone.X86_REG_XMM28] = x86_const.UC_X86_REG_XMM28,
  [capstone.X86_REG_XMM29] = x86_const.UC_X86_REG_XMM29,
	[capstone.X86_REG_XMM30] = x86_const.UC_X86_REG_XMM30,
  [capstone.X86_REG_XMM31] = x86_const.UC_X86_REG_XMM31,
  [capstone.X86_REG_YMM0] = x86_const.UC_X86_REG_YMM0,
  [capstone.X86_REG_YMM1] = x86_const.UC_X86_REG_YMM1,
  [capstone.X86_REG_YMM2] = x86_const.UC_X86_REG_YMM2,
	[capstone.X86_REG_YMM3] = x86_const.UC_X86_REG_YMM3,
  [capstone.X86_REG_YMM4] = x86_const.UC_X86_REG_YMM4,
  [capstone.X86_REG_YMM5] = x86_const.UC_X86_REG_YMM5,
  [capstone.X86_REG_YMM6] = x86_const.UC_X86_REG_YMM6,
  [capstone.X86_REG_YMM7] = x86_const.UC_X86_REG_YMM7,
	[capstone.X86_REG_YMM8] = x86_const.UC_X86_REG_YMM8,
  [capstone.X86_REG_YMM9] = x86_const.UC_X86_REG_YMM9,
  [capstone.X86_REG_YMM10] = x86_const.UC_X86_REG_YMM10,
  [capstone.X86_REG_YMM11] = x86_const.UC_X86_REG_YMM11,
  [capstone.X86_REG_YMM12] = x86_const.UC_X86_REG_YMM12,
	[capstone.X86_REG_YMM13] = x86_const.UC_X86_REG_YMM13,
  [capstone.X86_REG_YMM14] = x86_const.UC_X86_REG_YMM14,
  [capstone.X86_REG_YMM15] = x86_const.UC_X86_REG_YMM15,
  [capstone.X86_REG_YMM16] = x86_const.UC_X86_REG_YMM16,
  [capstone.X86_REG_YMM17] = x86_const.UC_X86_REG_YMM17,
	[capstone.X86_REG_YMM18] = x86_const.UC_X86_REG_YMM18,
  [capstone.X86_REG_YMM19] = x86_const.UC_X86_REG_YMM19,
  [capstone.X86_REG_YMM20] = x86_const.UC_X86_REG_YMM20,
  [capstone.X86_REG_YMM21] = x86_const.UC_X86_REG_YMM21,
  [capstone.X86_REG_YMM22] = x86_const.UC_X86_REG_YMM22,
	[capstone.X86_REG_YMM23] = x86_const.UC_X86_REG_YMM23,
  [capstone.X86_REG_YMM24] = x86_const.UC_X86_REG_YMM24,
  [capstone.X86_REG_YMM25] = x86_const.UC_X86_REG_YMM25,
  [capstone.X86_REG_YMM26] = x86_const.UC_X86_REG_YMM26,
  [capstone.X86_REG_YMM27] = x86_const.UC_X86_REG_YMM27,
	[capstone.X86_REG_YMM28] = x86_const.UC_X86_REG_YMM28,
  [capstone.X86_REG_YMM29] = x86_const.UC_X86_REG_YMM29,
  [capstone.X86_REG_YMM30] = x86_const.UC_X86_REG_YMM30,
  [capstone.X86_REG_YMM31] = x86_const.UC_X86_REG_YMM31,
  [capstone.X86_REG_ZMM0] = x86_const.UC_X86_REG_ZMM0,
	[capstone.X86_REG_ZMM1] = x86_const.UC_X86_REG_ZMM1,
  [capstone.X86_REG_ZMM2] = x86_const.UC_X86_REG_ZMM2,
  [capstone.X86_REG_ZMM3] = x86_const.UC_X86_REG_ZMM3,
  [capstone.X86_REG_ZMM4] = x86_const.UC_X86_REG_ZMM4,
  [capstone.X86_REG_ZMM5] = x86_const.UC_X86_REG_ZMM5,
	[capstone.X86_REG_ZMM6] = x86_const.UC_X86_REG_ZMM6,
  [capstone.X86_REG_ZMM7] = x86_const.UC_X86_REG_ZMM7,
  [capstone.X86_REG_ZMM8] = x86_const.UC_X86_REG_ZMM8,
  [capstone.X86_REG_ZMM9] = x86_const.UC_X86_REG_ZMM9,
  [capstone.X86_REG_ZMM10] = x86_const.UC_X86_REG_ZMM10,
	[capstone.X86_REG_ZMM11] = x86_const.UC_X86_REG_ZMM11,
  [capstone.X86_REG_ZMM12] = x86_const.UC_X86_REG_ZMM12,
  [capstone.X86_REG_ZMM13] = x86_const.UC_X86_REG_ZMM13,
  [capstone.X86_REG_ZMM14] = x86_const.UC_X86_REG_ZMM14,
  [capstone.X86_REG_ZMM15] = x86_const.UC_X86_REG_ZMM15,
	[capstone.X86_REG_ZMM16] = x86_const.UC_X86_REG_ZMM16,
  [capstone.X86_REG_ZMM17] = x86_const.UC_X86_REG_ZMM17,
  [capstone.X86_REG_ZMM18] = x86_const.UC_X86_REG_ZMM18,
  [capstone.X86_REG_ZMM19] = x86_const.UC_X86_REG_ZMM19,
  [capstone.X86_REG_ZMM20] = x86_const.UC_X86_REG_ZMM20,
	[capstone.X86_REG_ZMM21] = x86_const.UC_X86_REG_ZMM21,
  [capstone.X86_REG_ZMM22] = x86_const.UC_X86_REG_ZMM22,
  [capstone.X86_REG_ZMM23] = x86_const.UC_X86_REG_ZMM23,
  [capstone.X86_REG_ZMM24] = x86_const.UC_X86_REG_ZMM24,
  [capstone.X86_REG_ZMM25] = x86_const.UC_X86_REG_ZMM25,
	[capstone.X86_REG_ZMM26] = x86_const.UC_X86_REG_ZMM26,
  [capstone.X86_REG_ZMM27] = x86_const.UC_X86_REG_ZMM27,
  [capstone.X86_REG_ZMM28] = x86_const.UC_X86_REG_ZMM28,
  [capstone.X86_REG_ZMM29] = x86_const.UC_X86_REG_ZMM29,
  [capstone.X86_REG_ZMM30] = x86_const.UC_X86_REG_ZMM30,
	[capstone.X86_REG_ZMM31] = x86_const.UC_X86_REG_ZMM31,
  [capstone.X86_REG_R8B] = x86_const.UC_X86_REG_R8B,
  [capstone.X86_REG_R9B] = x86_const.UC_X86_REG_R9B,
  [capstone.X86_REG_R10B] = x86_const.UC_X86_REG_R10B,
  [capstone.X86_REG_R11B] = x86_const.UC_X86_REG_R11B,
	[capstone.X86_REG_R12B] = x86_const.UC_X86_REG_R12B,
  [capstone.X86_REG_R13B] = x86_const.UC_X86_REG_R13B,
  [capstone.X86_REG_R14B] = x86_const.UC_X86_REG_R14B,
  [capstone.X86_REG_R15B] = x86_const.UC_X86_REG_R15B,
  [capstone.X86_REG_R8D] = x86_const.UC_X86_REG_R8D,
	[capstone.X86_REG_R9D] = x86_const.UC_X86_REG_R9D,
  [capstone.X86_REG_R10D] = x86_const.UC_X86_REG_R10D,
  [capstone.X86_REG_R11D] = x86_const.UC_X86_REG_R11D,
  [capstone.X86_REG_R12D] = x86_const.UC_X86_REG_R12D,
  [capstone.X86_REG_R13D] = x86_const.UC_X86_REG_R13D,
	[capstone.X86_REG_R14D] = x86_const.UC_X86_REG_R14D,
  [capstone.X86_REG_R15D] = x86_const.UC_X86_REG_R15D,
  [capstone.X86_REG_R8W] = x86_const.UC_X86_REG_R8W,
  [capstone.X86_REG_R9W] = x86_const.UC_X86_REG_R9W,
  [capstone.X86_REG_R10W] = x86_const.UC_X86_REG_R10W,
	[capstone.X86_REG_R11W] = x86_const.UC_X86_REG_R11W,
  [capstone.X86_REG_R12W] = x86_const.UC_X86_REG_R12W,
  [capstone.X86_REG_R13W] = x86_const.UC_X86_REG_R13W,
  [capstone.X86_REG_R14W] = x86_const.UC_X86_REG_R14W,
  [capstone.X86_REG_R15W] = x86_const.UC_X86_REG_R15W,
	[capstone.X86_REG_BND0] = x86_const.UC_X86_REG_BND0,
  [capstone.X86_REG_BND1] = x86_const.UC_X86_REG_BND1,
  [capstone.X86_REG_BND2] = x86_const.UC_X86_REG_BND2,
  [capstone.X86_REG_BND3] = x86_const.UC_X86_REG_BND3,
}


local arch_pc = {
  [M.arch.X86_16] = x86_const.UC_X86_REG_IP,
  [M.arch.X86_32] = x86_const.UC_X86_REG_EIP,
  [M.arch.X86_64] = x86_const.UC_X86_REG_RIP,

  [M.arch.ARM_V6] = arm_const.UC_ARM_REG_PC,
  [M.arch.ARM_V7] = arm_const.UC_ARM_REG_PC,
  [M.arch.ARM_V8] = arm_const.UC_ARM_REG_PC,

  [M.arch.AARCH64] = aarch64_const.UC_ARM64_REG_PC,
}

local arch_sp = {
  [M.arch.X86_16] = x86_const.UC_X86_REG_SP,
  [M.arch.X86_32] = x86_const.UC_X86_REG_ESP,
  [M.arch.X86_64] = x86_const.UC_X86_REG_RSP,

  [M.arch.ARM_V6] = arm_const.UC_ARM_REG_SP,
  [M.arch.ARM_V7] = arm_const.UC_ARM_REG_SP,
  [M.arch.ARM_V8] = arm_const.UC_ARM_REG_SP,

  [M.arch.AARCH64] = aarch64_const.UC_ARM64_REG_SP,
}

-- Registers

local arch_reg = {
  [M.arch.X86_64] = {
    [x86_const.UC_X86_REG_AH] = { name = "ah", base = x86_const.UC_X86_REG_AX, },
    [x86_const.UC_X86_REG_AL] = { name = "al", base = x86_const.UC_X86_REG_AX, },
    [x86_const.UC_X86_REG_AX] = { name = "ax", base = x86_const.UC_X86_REG_EAX, },
    [x86_const.UC_X86_REG_BH] = { name = "bh", base = x86_const.UC_X86_REG_BX, },
    [x86_const.UC_X86_REG_BL] = { name = "bl", base = x86_const.UC_X86_REG_BX, },
    [x86_const.UC_X86_REG_BP] = { name = "bp", base = x86_const.UC_X86_REG_EBP, },
    [x86_const.UC_X86_REG_BPL] = { name = "bpl", base = x86_const.UC_X86_REG_BP, },
    [x86_const.UC_X86_REG_BX] = { name = "bx", base = x86_const.UC_X86_REG_EBX, },
    [x86_const.UC_X86_REG_CH] = { name = "ch", base = x86_const.UC_X86_REG_CX, },
    [x86_const.UC_X86_REG_CL] = { name = "cl", base = x86_const.UC_X86_REG_CX, },
    [x86_const.UC_X86_REG_CS] = { name = "cs", segment = true, },
    [x86_const.UC_X86_REG_CX] = { name = "cx", base = x86_const.UC_X86_REG_ECX, },
    [x86_const.UC_X86_REG_DH] = { name = "dh", base = x86_const.UC_X86_REG_DX, },
    [x86_const.UC_X86_REG_DI] = { name = "di", base = x86_const.UC_X86_REG_DX, },
    [x86_const.UC_X86_REG_DIL] = { name = "dil", base = x86_const.UC_X86_REG_DI, },
    [x86_const.UC_X86_REG_DL] = { name = "dl", base = x86_const.UC_X86_REG_DX, },
    [x86_const.UC_X86_REG_DS] = { name = "ds", segment = true, },
    [x86_const.UC_X86_REG_DX] = { name = "dx", base = x86_const.UC_X86_REG_EDX, },
    [x86_const.UC_X86_REG_EAX] = { name = "eax", base = x86_const.UC_X86_REG_RAX,},
    [x86_const.UC_X86_REG_EBP] = { name = "ebp", base = x86_const.UC_X86_REG_RBP, },
    [x86_const.UC_X86_REG_EBX] = { name = "ebx", base = x86_const.UC_X86_REG_RBX, },
    [x86_const.UC_X86_REG_ECX] = { name = "ecx", base = x86_const.UC_X86_REG_RCX, },
    [x86_const.UC_X86_REG_EDI] = { name = "edi", base = x86_const.UC_X86_REG_RDI, },
    [x86_const.UC_X86_REG_EDX] = { name = "edx", base = x86_const.UC_X86_REG_RDX, },
    [x86_const.UC_X86_REG_EFLAGS] = { name = "flags", flags = true, },
    [x86_const.UC_X86_REG_EIP] = { name = "eip", base = x86_const.UC_X86_REG_RIP, pc = true, },
    [x86_const.UC_X86_REG_ES] = { name = "es", segment = true, },
    [x86_const.UC_X86_REG_ESI] = { name = "esi", base = x86_const.UC_X86_REG_RSI, },
    [x86_const.UC_X86_REG_ESP] = { name = "esp", base = x86_const.UC_X86_REG_RSP, },
    [x86_const.UC_X86_REG_FPSW] = { name = "fpsw", fp = true, flags = true, },
    [x86_const.UC_X86_REG_FS] = { name = "fs", segment = true, },
    [x86_const.UC_X86_REG_GS] = { name = "gs", segment = true, },
    [x86_const.UC_X86_REG_IP] = { name = "ip", base = x86_const.UC_X86_REG_EIP, pc = true, },
    [x86_const.UC_X86_REG_RAX] = { name = "rax", },
    [x86_const.UC_X86_REG_RBP] = { name = "rbp", },
    [x86_const.UC_X86_REG_RBX] = { name = "rbx", },
    [x86_const.UC_X86_REG_RCX] = { name = "rcx", },
    [x86_const.UC_X86_REG_RDI] = { name = "rdi", },
    [x86_const.UC_X86_REG_RDX] = { name = "rdx", },
    [x86_const.UC_X86_REG_RIP] = { name = "rip", },
    [x86_const.UC_X86_REG_RSI] = { name = "rsi", },
    [x86_const.UC_X86_REG_RSP] = { name = "rsp", },
    [x86_const.UC_X86_REG_SI] = { name = "si", base = x86_const.UC_X86_REG_ESI, },
    [x86_const.UC_X86_REG_SIL] = { name = "sil", base = x86_const.UC_X86_REG_SI, },
    [x86_const.UC_X86_REG_SP] = { name = "sp", base = x86_const.UC_X86_REG_ESP, },
    [x86_const.UC_X86_REG_SPL] = { name = "spl", base = x86_const.UC_X86_REG_SP, },
    [x86_const.UC_X86_REG_SS] = { name = "ss", segment = true, },
    [x86_const.UC_X86_REG_CR0] = { name = "cr0", system = true, },
    [x86_const.UC_X86_REG_CR1] = { name = "cr1", system = true, },
    [x86_const.UC_X86_REG_CR2] = { name = "cr2", system = true, },
    [x86_const.UC_X86_REG_CR3] = { name = "cr3", system = true, },
    [x86_const.UC_X86_REG_CR4] = { name = "cr4", system = true, },
    --TODO: Why does reading it crash?
    -- Maybe Qemu supports it on target only when the host machine supports it?
    -- To check
    --[x86_const.UC_X86_REG_CR8] = { name = "cr8", },
    [x86_const.UC_X86_REG_DR0] = { name = "dr0", system = true, },
    [x86_const.UC_X86_REG_DR1] = { name = "dr1", system = true, },
    [x86_const.UC_X86_REG_DR2] = { name = "dr2", system = true, },
    [x86_const.UC_X86_REG_DR3] = { name = "dr3", system = true, },
    [x86_const.UC_X86_REG_DR4] = { name = "dr4", system = true, },
    [x86_const.UC_X86_REG_DR5] = { name = "dr5", system = true, },
    [x86_const.UC_X86_REG_DR6] = { name = "dr6", system = true, },
    [x86_const.UC_X86_REG_DR7] = { name = "dr7", system = true, },
    [x86_const.UC_X86_REG_FP0] = { name = "fp0", fp = true, },
    [x86_const.UC_X86_REG_FP1] = { name = "fp1", fp = true, },
    [x86_const.UC_X86_REG_FP2] = { name = "fp2", fp = true, },
    [x86_const.UC_X86_REG_FP3] = { name = "fp3", fp = true, },
    [x86_const.UC_X86_REG_FP4] = { name = "fp4", fp = true, },
    [x86_const.UC_X86_REG_FP5] = { name = "fp5", fp = true, },
    [x86_const.UC_X86_REG_FP6] = { name = "fp6", fp = true, },
    [x86_const.UC_X86_REG_FP7] = { name = "fp7", fp = true, },
    --TODO: As above
    --[x86_const.UC_X86_REG_K0] = { name = "k0", },
    --[x86_const.UC_X86_REG_K1] = { name = "k1", },
    --[x86_const.UC_X86_REG_K2] = { name = "k2", },
    --[x86_const.UC_X86_REG_K3] = { name = "k3", },
    --[x86_const.UC_X86_REG_K4] = { name = "k4", },
    --[x86_const.UC_X86_REG_K5] = { name = "k5", },
    --[x86_const.UC_X86_REG_K6] = { name = "k6", },
    --[x86_const.UC_X86_REG_K7] = { name = "k7", },
    --And this. XMM works] = { name = though
    --[x86_const.UC_X86_REG_MM0] = { name = "mm0", },
    --[x86_const.UC_X86_REG_MM1] = { name = "mm1", },
    --[x86_const.UC_X86_REG_MM2] = { name = "mm2", },
    --[x86_const.UC_X86_REG_MM3] = { name = "mm3", },
    --[x86_const.UC_X86_REG_MM4] = { name = "mm4", },
    --[x86_const.UC_X86_REG_MM5] = { name = "mm5", },
    --[x86_const.UC_X86_REG_MM6] = { name = "mm6", },
    --[x86_const.UC_X86_REG_MM7] = { name = "mm7", },
    [x86_const.UC_X86_REG_R8] = { name = "r8", },
    [x86_const.UC_X86_REG_R9] = { name = "r9", },
    [x86_const.UC_X86_REG_R10] = { name = "r10", },
    [x86_const.UC_X86_REG_R11] = { name = "r11", },
    [x86_const.UC_X86_REG_R12] = { name = "r12", },
    [x86_const.UC_X86_REG_R13] = { name = "r13", },
    [x86_const.UC_X86_REG_R14] = { name = "r14", },
    [x86_const.UC_X86_REG_R15] = { name = "r15", },
    [x86_const.UC_X86_REG_ST0] = { name = "st0", fp = true, },
    [x86_const.UC_X86_REG_ST1] = { name = "st1", fp = true, },
    [x86_const.UC_X86_REG_ST2] = { name = "st2", fp = true, },
    [x86_const.UC_X86_REG_ST3] = { name = "st3", fp = true, },
    [x86_const.UC_X86_REG_ST4] = { name = "st4", fp = true, },
    [x86_const.UC_X86_REG_ST5] = { name = "st5", fp = true, },
    [x86_const.UC_X86_REG_ST6] = { name = "st6", fp = true, },
    [x86_const.UC_X86_REG_ST7] = { name = "st7", fp = true, },
    [x86_const.UC_X86_REG_XMM0] = { name = "xmm0", base = x86_const.UC_X86_REG_YMM0, vector = true, },
    [x86_const.UC_X86_REG_XMM1] = { name = "xmm1", base = x86_const.UC_X86_REG_YMM1, vector = true, },
    [x86_const.UC_X86_REG_XMM2] = { name = "xmm2", base = x86_const.UC_X86_REG_YMM2, vector = true, },
    [x86_const.UC_X86_REG_XMM3] = { name = "xmm3", base = x86_const.UC_X86_REG_YMM3, vector = true, },
    [x86_const.UC_X86_REG_XMM4] = { name = "xmm4", base = x86_const.UC_X86_REG_YMM4, vector = true, },
    [x86_const.UC_X86_REG_XMM5] = { name = "xmm5", base = x86_const.UC_X86_REG_YMM5, vector = true, },
    [x86_const.UC_X86_REG_XMM6] = { name = "xmm6", base = x86_const.UC_X86_REG_YMM6, vector = true, },
    [x86_const.UC_X86_REG_XMM7] = { name = "xmm7", base = x86_const.UC_X86_REG_YMM7, vector = true, },
    [x86_const.UC_X86_REG_XMM8] = { name = "xmm8", base = x86_const.UC_X86_REG_YMM8, vector = true, },
    [x86_const.UC_X86_REG_XMM9] = { name = "xmm9", base = x86_const.UC_X86_REG_YMM9, vector = true, },
    [x86_const.UC_X86_REG_XMM10] = { name = "xmm10", base = x86_const.UC_X86_REG_YMM10, vector = true, },
    [x86_const.UC_X86_REG_XMM11] = { name = "xmm11", base = x86_const.UC_X86_REG_YMM11, vector = true, },
    [x86_const.UC_X86_REG_XMM12] = { name = "xmm12", base = x86_const.UC_X86_REG_YMM12, vector = true, },
    [x86_const.UC_X86_REG_XMM13] = { name = "xmm13", base = x86_const.UC_X86_REG_YMM13, vector = true, },
    [x86_const.UC_X86_REG_XMM14] = { name = "xmm14", base = x86_const.UC_X86_REG_YMM14, vector = true, },
    [x86_const.UC_X86_REG_XMM15] = { name = "xmm15", base = x86_const.UC_X86_REG_YMM15, vector = true, },
    --TODO: AVX-512 registers are not supported
    --[x86_const.UC_X86_REG_XMM16] = { name = "xmm16", },
    --[x86_const.UC_X86_REG_XMM17] = { name = "xmm17", },
    --[x86_const.UC_X86_REG_XMM18] = { name = "xmm18", },
    --[x86_const.UC_X86_REG_XMM19] = { name = "xmm19", },
    --[x86_const.UC_X86_REG_XMM20] = { name = "xmm20", },
    --[x86_const.UC_X86_REG_XMM21] = { name = "xmm21", },
    --[x86_const.UC_X86_REG_XMM22] = { name = "xmm22", },
    --[x86_const.UC_X86_REG_XMM23] = { name = "xmm23", },
    --[x86_const.UC_X86_REG_XMM24] = { name = "xmm24", },
    --[x86_const.UC_X86_REG_XMM25] = { name = "xmm25", },
    --[x86_const.UC_X86_REG_XMM26] = { name = "xmm26", },
    --[x86_const.UC_X86_REG_XMM27] = { name = "xmm27", },
    --[x86_const.UC_X86_REG_XMM28] = { name = "xmm28", },
    --[x86_const.UC_X86_REG_XMM29] = { name = "xmm29", },
    --[x86_const.UC_X86_REG_XMM30] = { name = "xmm30", },
    --[x86_const.UC_X86_REG_XMM31] = { name = "xmm31", },
    [x86_const.UC_X86_REG_YMM0] = { name = "ymm0", vector = true, },
    [x86_const.UC_X86_REG_YMM1] = { name = "ymm1", vector = true, },
    [x86_const.UC_X86_REG_YMM2] = { name = "ymm2", vector = true, },
    [x86_const.UC_X86_REG_YMM3] = { name = "ymm3", vector = true, },
    [x86_const.UC_X86_REG_YMM4] = { name = "ymm4", vector = true, },
    [x86_const.UC_X86_REG_YMM5] = { name = "ymm5", vector = true, },
    [x86_const.UC_X86_REG_YMM6] = { name = "ymm6", vector = true, },
    [x86_const.UC_X86_REG_YMM7] = { name = "ymm7", vector = true, },
    [x86_const.UC_X86_REG_YMM8] = { name = "ymm8", vector = true, },
    [x86_const.UC_X86_REG_YMM9] = { name = "ymm9", vector = true, },
    [x86_const.UC_X86_REG_YMM10] = { name = "ymm10", vector = true, },
    [x86_const.UC_X86_REG_YMM11] = { name = "ymm11", vector = true, },
    [x86_const.UC_X86_REG_YMM12] = { name = "ymm12", vector = true, },
    [x86_const.UC_X86_REG_YMM13] = { name = "ymm13", vector = true, },
    [x86_const.UC_X86_REG_YMM14] = { name = "ymm14", vector = true, },
    [x86_const.UC_X86_REG_YMM15] = { name = "ymm15", vector = true, },
    --[x86_const.UC_X86_REG_YMM16] = { name = "ymm16", },
    --[x86_const.UC_X86_REG_YMM17] = { name = "ymm17", },
    --[x86_const.UC_X86_REG_YMM18] = { name = "ymm18", },
    --[x86_const.UC_X86_REG_YMM19] = { name = "ymm19", },
    --[x86_const.UC_X86_REG_YMM20] = { name = "ymm20", },
    --[x86_const.UC_X86_REG_YMM21] = { name = "ymm21", },
    --[x86_const.UC_X86_REG_YMM22] = { name = "ymm22", },
    --[x86_const.UC_X86_REG_YMM23] = { name = "ymm23", },
    --[x86_const.UC_X86_REG_YMM24] = { name = "ymm24", },
    --[x86_const.UC_X86_REG_YMM25] = { name = "ymm25", },
    --[x86_const.UC_X86_REG_YMM26] = { name = "ymm26", },
    --[x86_const.UC_X86_REG_YMM27] = { name = "ymm27", },
    --[x86_const.UC_X86_REG_YMM28] = { name = "ymm28", },
    --[x86_const.UC_X86_REG_YMM29] = { name = "ymm29", },
    --[x86_const.UC_X86_REG_YMM30] = { name = "ymm30", },
    --[x86_const.UC_X86_REG_YMM31] = { name = "ymm31", },
    --[[
    [x86_const.UC_X86_REG_ZMM0] = { name = "zmm0", },
    [x86_const.UC_X86_REG_ZMM1] = { name = "zmm1", },
    [x86_const.UC_X86_REG_ZMM2] = { name = "zmm2", },
    [x86_const.UC_X86_REG_ZMM3] = { name = "zmm3", },
    [x86_const.UC_X86_REG_ZMM4] = { name = "zmm4", },
    [x86_const.UC_X86_REG_ZMM5] = { name = "zmm5", },
    [x86_const.UC_X86_REG_ZMM6] = { name = "zmm6", },
    [x86_const.UC_X86_REG_ZMM7] = { name = "zmm7", },
    [x86_const.UC_X86_REG_ZMM8] = { name = "zmm8", },
    [x86_const.UC_X86_REG_ZMM9] = { name = "zmm9", },
    [x86_const.UC_X86_REG_ZMM10] = { name = "zmm10", },
    [x86_const.UC_X86_REG_ZMM11] = { name = "zmm11", },
    [x86_const.UC_X86_REG_ZMM12] = { name = "zmm12", },
    [x86_const.UC_X86_REG_ZMM13] = { name = "zmm13", },
    [x86_const.UC_X86_REG_ZMM14] = { name = "zmm14", },
    [x86_const.UC_X86_REG_ZMM15] = { name = "zmm15", },
    [x86_const.UC_X86_REG_ZMM16] = { name = "zmm16", },
    [x86_const.UC_X86_REG_ZMM17] = { name = "zmm17", },
    [x86_const.UC_X86_REG_ZMM18] = { name = "zmm18", },
    [x86_const.UC_X86_REG_ZMM19] = { name = "zmm19", },
    [x86_const.UC_X86_REG_ZMM20] = { name = "zmm20", },
    [x86_const.UC_X86_REG_ZMM21] = { name = "zmm21", },
    [x86_const.UC_X86_REG_ZMM22] = { name = "zmm22", },
    [x86_const.UC_X86_REG_ZMM23] = { name = "zmm23", },
    [x86_const.UC_X86_REG_ZMM24] = { name = "zmm24", },
    [x86_const.UC_X86_REG_ZMM25] = { name = "zmm25", },
    [x86_const.UC_X86_REG_ZMM26] = { name = "zmm26", },
    [x86_const.UC_X86_REG_ZMM27] = { name = "zmm27", },
    [x86_const.UC_X86_REG_ZMM28] = { name = "zmm28", },
    [x86_const.UC_X86_REG_ZMM29] = { name = "zmm29", },
    [x86_const.UC_X86_REG_ZMM30] = { name = "zmm30", },
    [x86_const.UC_X86_REG_ZMM31] = { name = "zmm31", },
    ]]
    [x86_const.UC_X86_REG_R8B] = { name = "r8b", base = x86_const.UC_X86_REG_R8, },
    [x86_const.UC_X86_REG_R9B] = { name = "r9b", base = x86_const.UC_X86_REG_R9, },
    [x86_const.UC_X86_REG_R10B] = { name = "r10b", base = x86_const.UC_X86_REG_R10, },
    [x86_const.UC_X86_REG_R11B] = { name = "r11b", base = x86_const.UC_X86_REG_R11, },
    [x86_const.UC_X86_REG_R12B] = { name = "r12b", base = x86_const.UC_X86_REG_R12, },
    [x86_const.UC_X86_REG_R13B] = { name = "r13b", base = x86_const.UC_X86_REG_R13, },
    [x86_const.UC_X86_REG_R14B] = { name = "r14b", base = x86_const.UC_X86_REG_R14, },
    [x86_const.UC_X86_REG_R15B] = { name = "r15b", base = x86_const.UC_X86_REG_R15, },
    [x86_const.UC_X86_REG_R8D] = { name = "r8d", base = x86_const.UC_X86_REG_R8, },
    [x86_const.UC_X86_REG_R9D] = { name = "r9d", base = x86_const.UC_X86_REG_R9, },
    [x86_const.UC_X86_REG_R10D] = { name = "r10d", base = x86_const.UC_X86_REG_R10, },
    [x86_const.UC_X86_REG_R11D] = { name = "r11d", base = x86_const.UC_X86_REG_R11, },
    [x86_const.UC_X86_REG_R12D] = { name = "r12d", base = x86_const.UC_X86_REG_R12, },
    [x86_const.UC_X86_REG_R13D] = { name = "r13d", base = x86_const.UC_X86_REG_R13, },
    [x86_const.UC_X86_REG_R14D] = { name = "r14d", base = x86_const.UC_X86_REG_R14, },
    [x86_const.UC_X86_REG_R15D] = { name = "r15d", base = x86_const.UC_X86_REG_R15, },
    [x86_const.UC_X86_REG_R8W] = { name = "r8w", base = x86_const.UC_X86_REG_R8, },
    [x86_const.UC_X86_REG_R9W] = { name = "r9w", base = x86_const.UC_X86_REG_R9, },
    [x86_const.UC_X86_REG_R10W] = { name = "r10w", base = x86_const.UC_X86_REG_R10, },
    [x86_const.UC_X86_REG_R11W] = { name = "r11w", base = x86_const.UC_X86_REG_R11, },
    [x86_const.UC_X86_REG_R12W] = { name = "r12w", base = x86_const.UC_X86_REG_R12, },
    [x86_const.UC_X86_REG_R13W] = { name = "r13w", base = x86_const.UC_X86_REG_R13, },
    [x86_const.UC_X86_REG_R14W] = { name = "r14w", base = x86_const.UC_X86_REG_R14, },
    [x86_const.UC_X86_REG_R15W] = { name = "r15w", base = x86_const.UC_X86_REG_R15, },
    --[x86_const.UC_X86_REG_BND0] = { name = "bnd0", },
    --[x86_const.UC_X86_REG_BND1] = { name = "bnd1", },
    --[x86_const.UC_X86_REG_BND2] = { name = "bnd2", },
    --[x86_const.UC_X86_REG_BND3] = { name = "bnd3", },
  }
}

M.isopen = false

M.open = function(_arch, reg)
  local params = arch_params[_arch]
  if params == nil then
    error(string.format("Architecture parameters undefined arch=[%s]", tostring(_arch)))
  end

  local res = unicorn.open(params.unicorn_arch, params.unicorn_mode)
  --[[
  local status, res
  status, res = pcall(function() unicorn.open(params.unicorn_arch, params.unicorn_mode) end)
  if not status then
    error(string.format("Failed to open Unicorn engine with parameters arch=[%s] mode=[%s]",
      tostring(params.unicorn_arch),
      tostring(params.unicorn_mode)))
  end
  ]]
  M.engine = res

  reg._arch = _arch
  reg._pc = arch_pc[_arch]
  reg._sp = arch_sp[_arch]
  reg.def = arch_reg[_arch]

  reg.name = function(reg_id)
    print(reg_id)
    local reg_def = arch_reg[reg._arch][reg_id]
    if reg_def ~= nil then
      return reg_def.name
    else
      return "???" .. tostring(reg_id)
    end
  end

  -- Converts Capstone's register id to Unicorn's one
  reg.disasm_reg_id = function(disasm_reg_id)
    --TODO: Make architecture-specific
    return x86_capstone_to_unicorn_reg_map[disasm_reg_id]
  end


  local status, handle
  status, handle = capstone.open(params.capstone_arch, params.capstone_mode)
  if not status then
    error(string.format("Failed to open Capstone with parameters arch=[%s] mode=[%s]",
      tostring(params.capstone_arch),
      tostring(params.capstone_mode)))
  end
  capstone.option(handle, capstone.CS_OPT_DETAIL, capstone.CS_OPT_ON)
  capstone.option(handle, capstone.CS_OPT_SKIPDATA, capstone.CS_OPT_ON)
  M.disasm = handle
end

M.close = function()
  if M.isopen then
    if M.engine ~= nil then
      pcall(M.engine:close())
      M.engine = nil
    end
    if M.disasm ~= nil then
      pcall(capstone.close(M.disasm))
      M.disasm = nil
    end
    M.isopen = false
  end
end




return M

