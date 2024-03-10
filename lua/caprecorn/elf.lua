-- ELF file loader
-- Inspired by and stolen from Qiling
local M = {}

require("strbuf")
local _log = require("_log")

local _arch = require("arch")
M.arch = _arch.arch

M.setup = function(emu, mem, reg)
  M.emu = emu
  M.mem = mem
  M.reg = reg
end

-- Linux so far
local _addresses = {
  [M.arch.X86_32] = {
    stack_address = 0x7ff0d000,
    stack_size = 0x30000,
    load_address = 0x56555000,
    interp_address = 0x047ba000,
    mmap_address = 0x90000000,
  },
  [M.arch.X86_64] = {
    stack_address = 0x7ffffffde000,
    stack_size = 0x30000,
    load_address = 0x555555554000,
    interp_address = 0x7ffff7dd5000,
    mmap_address = 0x7fffb7dd6000,
    vsyscall_address = 0xffffffffff600000,
    gdt_addr = 0x30000,
    gdt_limit = 0x1000,
    gdt_entry_size = 0x8,
    gdt_entries = 16, -- ??
  },
}

local loader_params = {
  env = {},
  argv = {},
}

local function x8664_init_gdt(addr)
  -- Map memory for GDT
  M.mem.map(addr.gdt_addr, addr.gdt_limit)

  -- Initailize GDTR
  local gdtr_value = string.from(0, 8)
    .. string.from(addr.gdt_addr, 8)
    .. string.from(addr.gdt_limit, 4)
    .. string.from(0, 4)
  M.reg.write_buf(C.reg.x86.gdtr, gdtr_value)

  -- Initialize GDT contents
  -- See Qiling source for constants meaning
  local index
  local entry
  local selector

  --- CS
  index = 6
  entry = string.from({ 0xff, 0xff, 0x00, 0x00, 0x00, 0xfe, 0xcf, 0x00 })
  selector = 0x33
  M.mem.write(addr.gdt_addr + index * addr.gdt_entry_size, entry)
  M.reg.write(M.reg.x86.cs, selector)

  --- SS
  index = 5
  entry = string.from({0xff, 0xff, 0x00, 0x00, 0x00, 0x96, 0xcf, 0x00 })
  selector = 0x28
  M.mem.write(addr.gdt_addr + index * addr.gdt_entry_size, entry)
  M.reg.write(M.reg.x86.ss, selector)

  --- DS = ES = 0

  local msr_value

  -- GS
  msr_value = string.from({ 0xc0000101, 0x6000000}, 8)
  M.reg.write_buf(M.reg.x86.msr, msr_value)
end


local function x8664_init(addr)
  x8664_init_gdt(addr)
end

local init = {
  [M.arch.X86_64] = x8664_init,
}

M.init = function()
  local arch = M.emu.arch
  local addresses = _addresses[arch]
  init[arch](addresses)
end

return M
