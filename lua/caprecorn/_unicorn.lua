local M = {}

-- Dependencies: Unicorn and Capstone

local unicorn = require("unicorn")
local unicorn_const = require("unicorn.unicorn_const")

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
    capstone_arch = capstone.CS_ARCH_AARCH64,
    capstone_mode = capstone.CS_MODE_ARM,
  },
}


M.isopen = false

M.open = function(_arch)
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
  print("Unicorn engine open", M.engine)

  local status
  status, res = capstone.open(params.capstone_arch, params.capstone_mode)
  if not status then
    error(string.format("Failed to open Capstone with parameters arch=[%s] mode=[%s]",
      tostring(params.capstone_arch),
      tostring(params.capstone_mode)))
  end
  M.disasm = res
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

