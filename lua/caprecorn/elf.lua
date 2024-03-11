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
    gdt_entries = 16,
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

M.loadfile = function(filename)
  local bytes

  local fdesc = io.open(filename)
  if fdesc ~= nil then
    bytes = fdesc:read("*all")
    fdesc:close()
  else
    error("Failed to open ELF file [%s]", filename)
  end

  M.load(bytes)
end

local ET_EXEC = 2
local ET_DYN = 3

local PT_LOAD = 1

M.load = function(bytes)
  local elf = bytes
  local addresses = _addresses[M.emu.arch]
  --TODO: map stack here as in QlLoaderELF? (Most likely they took the logic from Linux kernel)
  -- Maybe better let user specify it explicitly
  -- What is stack segment in ELF then, if we specify it on start?
  print("ELF file size", #bytes)
  local magic = elf:i32(0)
  if magic ~= ("\127ELF"):i32() then
    error("ELF magic identifier not found")
  end

  local load_addr
  local e_type = elf:i16(0x10)
  if e_type == ET_EXEC then
    load_addr = 0
  elseif e_type == ET_DYN then
    load_addr = addresses.load_address
  else
    error(string.format("ELF type should be either EXEC or DYN, e_type=[%d]", e_type))
  end

  local ei_class = elf:i8(0x4)
  local is_32 = ei_class == 1
  local is_64 = ei_class == 2

  if not is_32 and not is_64 then
    error(string.format("ELF type should be either 32- or 64-bit, e_idend[EI_CLASS]=%d", ei_class))
  end

  local e_phnum
  if is_32 then e_phnum = elf:i16(0x2c) else e_phnum = elf:i16(0x38) end
  if e_phnum == 0xffff then
    error("ELF program headers count >= 0xffff, unsupported")
    --[[# If the number of program headers is greater than or equal to
        # PN_XNUM (0xffff), this member has the value PN_XNUM
        # (0xffff). The actual number of program header table entries
        # is contained in the sh_info field of the section header at
        # index 0.
    ]]
  end

  local e_phoff
  local e_phentsize
  if is_32 then e_phoff = elf:i32(0x1c) else e_phoff = elf:i64(0x24) end
  if is_32 then e_phentsize = elf:i16(0x2a) else e_phentsize = elf:i64(0x36) end

  local segments = {}
  for i = 0, e_phnum - 1 do
    local segment_offset = e_phoff + i * e_phentsize
    local p_type = elf:i32(segment_offset + 0x0)
    if p_type == PT_LOAD then
      local p_vaddr
      if is_32 then p_vaddr = elf:i32(segment_offset + 0x08) else e_phentsize = elf:i64(segment_offset + 0x10) end

      table.insert(segments, { segment_offset = segment_offset, p_vaddr = p_vaddr, })
    end
  end
  table.sort(segments, function(s1, s2) return s1.p_vaddr < s2.p_vaddr end)

  --TODO: Continue at load_elf_segments(): for seg in load_segments: ...
end

return M
