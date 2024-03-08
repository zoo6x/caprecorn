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



local arch_reg = {
  [M.arch.X86_64] = {
    { x86_const.UC_X86_REG_RAX, "rax" },
    { x86_const.UC_X86_REG_RBX, "rbx" },
    { x86_const.UC_X86_REG_RCX, "rcx" },
    { x86_const.UC_X86_REG_RDX, "rdx" },
    { x86_const.UC_X86_REG_RSI, "rsi" },
    { x86_const.UC_X86_REG_RDI, "rdi" },
    { x86_const.UC_X86_REG_RSP, "rsp" },
    { x86_const.UC_X86_REG_RIP, "rip" },
    { x86_const.UC_X86_REG_R8,  "r8"  },
    { x86_const.UC_X86_REG_R9,  "r9"  },
    { x86_const.UC_X86_REG_R10, "r10" },
    { x86_const.UC_X86_REG_R11, "r11" },
    { x86_const.UC_X86_REG_R12, "r12" },
    { x86_const.UC_X86_REG_R13, "r13" },
    { x86_const.UC_X86_REG_R14, "r14" },
    { x86_const.UC_X86_REG_R15, "r15" },
  }
}

M.isopen = false

M.open = function(_arch, reg)
  local params = arch_params[_arch]
  if params == nil then
    error(string.format("Architecture parameters underined arch=[%s]", tostring(_arch)))
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

  reg._pc = arch_pc[_arch]
  reg._sp = arch_sp[_arch]
  reg.def = arch_reg[_arch]

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

