local M = {}

local unicorn_const = require("unicorn.unicorn_const")

local capstone = require("capstone")

-- Architecture: CPU, bit width

local arch = {
  X86_16 = 11,
  X86_32 = 12,
  X86_64 = 13,

  ARM = 21,
  ARM_V6 = 23,
  ARM_V7 = 24,
  ARM_V8 = 25,

  AARCH64 = 29,
}
M.arch = arch

return M

