-- ELF file loader
-- Inspired by and stolen from Qiling
local M = {}

local bit = require("bit")

require("str")

local _log = require("_log")

local _arch = require("arch")
M.arch = _arch.arch

-- Assign mmap_address here
local sys = require("sys")

M.setup = function(emu, mem, reg)
  M.emu = emu
  M.mem = mem
  M.reg = reg
end

-- Linux so far
local _addresses = {
  [M.arch.X86_32] = {
    pointer_size = 4,

    stack_address = 0x7ff0d000,
    stack_size = 0x30000,
    load_address = 0x56555000,
    interp_address = 0x047ba000,
    mmap_address = 0x90000000,

    gdt_addr = 0x30000,
    gdt_limit = 0x1000,
    gdt_entry_size = 0x8,
    gdt_entries = 16,
  },
  [M.arch.X86_64] = {
    pointer_size = 8,

    stack_address = 0x7ffffffd0000,
    -- stack_size = 0x21000,
    stack_size = 0x30000,
    load_address = 0x555555554000,
    -- interp_address = 0x7ffff7fcf000,
    interp_address = 0x7ffff7dd5000, -- 0x00007ffff7fcf000, -- ,
    mmap_address   = 0x7fffb7dd6000, -- 0x00007ffff7fc9000, -- ,
    vsyscall_address = 0xffffffffff600000,

    gdt_addr = 0x30000,
    gdt_limit = 0x1000,
    gdt_entry_size = 0x8,
    gdt_entries = 16,
  },
}

local function x8664_init_gdt(addr)
  -- Map memory for GDT
  _log.write("Mapping GDT")
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

M.loadfile = function(filename, opts)
  local bytes

  local fdesc = io.open(filename)
  if fdesc ~= nil then
    bytes = fdesc:read("*all")
    fdesc:close()
  else
    error("Failed to open ELF file [%s]", filename)
  end

  opts = opts or {}
  opts.program = filename

  return M.load(bytes, opts)
end

-- Loading ELF

local ET_EXEC = 2
local ET_DYN = 3

local PT_LOAD = 1
local PT_INTERP = 3

local PF_EXEC = 1
local PF_WRITE = 2
local PF_READ = 4

local AUXV = {
    AT_NULL     = 0,
    AT_IGNORE   = 1,
    AT_EXECFD   = 2,
    AT_PHDR     = 3,
    AT_PHENT    = 4,
    AT_PHNUM    = 5,
    AT_PAGESZ   = 6,
    AT_BASE     = 7,
    AT_FLAGS    = 8,
    AT_ENTRY    = 9,
    AT_NOTELF   = 10,
    AT_UID      = 11,
    AT_EUID     = 12,
    AT_GID      = 13,
    AT_EGID     = 14,
    AT_PLATFORM = 15,
    AT_HWCAP    = 16,
    AT_CLKTCK   = 17,
    AT_SECURE   = 23,
    AT_BASE_PLATFORM = 24,
    AT_RANDOM   = 25,
    AT_HWCAP2   = 26,
    AT_EXECFN   = 31,
}

M.load = function(bytes, opts)
  _log.write("ELF load start")
  local res = {}

  res.size = #bytes

  opts = opts or {}
  local rootfs = opts.rootfs or "/"

  local elf = bytes
  local addresses = _addresses[M.emu.arch]

  local stack_addr = addresses.stack_address + addresses.stack_size
  if opts.map_stack ~= false then
    _log.write("Mapping stack")
    M.mem.map(addresses.stack_address, addresses.stack_size)
    _log.write(string.format("Stack: %016x - %016x", addresses.stack_address, stack_addr))
    res.sp = stack_addr
    res.stack_addr = addresses.stack_address
    res.stack_size = addresses.stack_size
    res.stack_end = stack_addr
  end

  _log.write("ELF file size = " .. tostring(#bytes))
  local magic = elf:i32(0)
  if magic ~= ("\127ELF"):i32() then
    error("ELF magic identifier not found")
  end

  local load_addr
  if opts.load_addr == nil then
    local e_type = elf:i16(0x10)
    if e_type == ET_EXEC then
      load_addr = 0
    elseif e_type == ET_DYN then
      load_addr = addresses.load_address
    else
      error(string.format("ELF type should be either EXEC or DYN, e_type=[%d]", e_type))
    end
  else
    load_addr = opts.load_addr
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
  if is_32 then e_phoff = elf:i32(0x1c) else e_phoff = elf:i64(0x20) end
  if is_32 then e_phentsize = elf:i16(0x2a) else e_phentsize = elf:i16(0x36) end

  _log.write(string.format("e_phnum = %2d e_phoff = %016x e_phentsize = %016x", e_phnum, e_phoff, e_phentsize))

  local interp_name
  local load_segments = {}
  for i = 0, e_phnum - 1 do
    local segment_offset = e_phoff + i * e_phentsize
    local p_type = elf:i32(segment_offset + 0x0)
    local p_flags
    local p_vaddr
    local p_memsz
    local p_filesz
    local p_offset
    if is_32 then p_flags = elf:i32(segment_offset + 0x18) else p_flags = elf:i32(segment_offset + 0x04) end
    if is_32 then p_vaddr = elf:i32(segment_offset + 0x08) else p_vaddr = elf:i64(segment_offset + 0x10) end
    if is_32 then p_memsz = elf:i32(segment_offset + 0x14) else p_memsz = elf:i64(segment_offset + 0x28) end
    if is_32 then p_filesz = elf:i32(segment_offset + 0x10) else p_filesz = elf:i64(segment_offset + 0x20) end
    if is_32 then p_offset = elf:i32(segment_offset + 0x04) else p_offset = elf:i64(segment_offset + 0x08) end
    _log.write(string.format("Segment %2d offset = %016x p_type = %08x p_flags = %08x p_offset = %08x p_memsz = %08x p_filesz = %08x",
      i, segment_offset, p_type, p_flags, p_offset, p_memsz, p_filesz))
    if p_type == PT_LOAD then

      local segment = {
        p_offset = p_offset,
        p_vaddr = p_vaddr,
        p_memsz = p_memsz,
        p_filesz = p_filesz,
        p_flags = p_flags,
      }
      table.insert(load_segments, segment)
    elseif p_type == PT_INTERP then
      interp_name = elf:cstr(p_offset)
    end
  end
  table.sort(load_segments, function(s1, s2) return s1.p_vaddr < s2.p_vaddr end)

  local function seg_perm_to_uc_prot(perm)
    local prot = 0

    if bit.band(perm, PF_EXEC) ~= 0 then
        prot = bit.bor(prot, M.mem.PROT_EXEC)
    end

    if bit.band(perm, PF_WRITE) ~= 0 then
        prot = bit.bor(prot, M.mem.PROT_WRITE)
    end

    if bit.band(perm, PF_READ) ~= 0 then
        prot = bit.bor(prot, M.mem.PROT_READ)
    end

    return prot
  end

  _log.write("Load segments:")
  local load_regions = {}
  for i, segment in ipairs(load_segments) do
    local lbound = load_addr + segment.p_vaddr
    local ubound = lbound + segment.p_memsz
    local perms = seg_perm_to_uc_prot(segment.p_flags)
    _log.write(string.format("%5d  %016x - %016x perms = %d", i, lbound, ubound, perms))
    lbound = M.mem.align(lbound, M.mem.PAGESIZE)
    ubound = M.mem.align_up(ubound, M.mem.PAGESIZE)
    if #load_regions > 0 then
      local prev_lbound, prev_ubound, prev_perms = unpack(load_regions[#load_regions])
      if lbound == prev_ubound then
        if perms == prev_perms then
          load_regions[#load_regions] = { prev_lbound, ubound, prev_perms }
        else
          load_regions[#load_regions + 1] = { lbound, ubound, perms }
        end
      elseif lbound > prev_ubound then
        load_regions[#load_regions + 1] = { lbound, ubound, perms }
      elseif lbound < prev_ubound then
        error("Overlapping segments")
      end
    else
      table.insert(load_regions, { lbound, ubound, perms })
    end
  end

  _log.write("Load regions:")
  for i, region in ipairs(load_regions) do
    local lbound = region[1]
    local ubound = region[2]
    local perms = region[3]
    local start = lbound
    local size = ubound - lbound
    _log.write(string.format("%5d  %016x - %016x  size = %016x perms = %d", i, lbound, ubound, size, perms))
    M.mem.map(start, size, perms)
  end

  local mem_start = 0
  local mem_end = 0
  local mem_size

  if #load_regions > 0 then
    mem_start = load_regions[1][1]
    mem_end = load_regions[#load_regions][2]
  end
  mem_size = mem_end - mem_start

  res.mem_start = mem_start
  res.mem_end = mem_end
  res.mem_size = mem_size

  _log.write(string.format("Memory %016x - %016x", mem_start, mem_end))

  _log.write("Writing segments:")
  for i, segment in ipairs(load_segments) do
    local segment_bytes = elf:sub(segment.p_offset + 1, segment.p_offset + segment.p_filesz)
    M.mem.write(load_addr + segment.p_vaddr, segment_bytes)
    _log.write(string.format("%5d  %016x size = %016x p_offset = %016x", i, load_addr + segment.p_vaddr, #segment_bytes, segment.p_offset))
  end

  local e_entry
  local entry
  if is_32 then e_entry = elf:i32(0x18) else e_entry = elf:i64(0x18) end
  entry = load_addr + e_entry
  res.entry = entry
  _log.write(string.format("Entry: %016x", entry))

  -- Loading interpreter
  if interp_name ~= nil then
    _log.write("Interpreter: " .. interp_name)
    local interp_addr = 0

    --TODO: If interpreter is not position-independent, it has to be loaded at some fixed address
    -- But this should only be the case with old interpreters, so ignore it for now
    interp_name = rootfs .. interp_name

    local interp_elf = M.loadfile(interp_name,
      {
        map_stack = false,
        load_addr = addresses.interp_address,
        rootfs = opts.rootfs,
      })
    local interp_entry = interp_elf.entry
    res.interp_entry = interp_entry
  end

  -- If loading an interpreter or a library (?)
  --TODO: Maybe this should be an explicit parameter
  if opts.map_stack == false then
    return res
  end

  M.emu.brk_addr = mem_end + 0x2000

  -- Assign mmap_address for mmap syscall address to use
  -- TODO: Ugly, but temporary
  sys.brk_addr = M.emu.brk_addr
  sys.mmap_addr = addresses.mmap_address
  sys.stack_size = addresses.stack_size
  _log.write(string.format("mmap_address is 0x%016x", sys.mmap_addr))
  sys.rootfs = rootfs

  local function push_str(top, s)
    local data = s .. '\000'
    top = M.mem.align(top - #data, addresses.pointer_size)
    M.mem.write(top, data)
    --_log.write(string.format("new_stack = %016x", top))
    return top
  end

  local function arch_bytes(v)
    local res
    if is_32 then
      res = string.from(v, 4)
    else
      res = string.from(v, 8)
    end
    return res
  end
  -- Push argc, argv and env onto stack
  local elf_table = ""
  local new_stack = stack_addr
  _log.write(string.format("new_stack = %016x", new_stack))

  local argv = opts.argv or {}
  local argc = #argv

  local argc_bytes = arch_bytes(argc)
  elf_table = elf_table:append(argc_bytes)
  for _, arg in ipairs(argv) do
    new_stack = push_str(new_stack, arg)
    local new_stack_bytes = arch_bytes(new_stack)
    elf_table = elf_table:append(new_stack_bytes)
  end
  local sentinel_bytes = arch_bytes(0)
  elf_table = elf_table:append(sentinel_bytes)

  local env = opts.env or {}
  for _, ev in ipairs(env) do
    new_stack = push_str(new_stack, ev)
    local new_stack_bytes = arch_bytes(new_stack)
    elf_table = elf_table:append(new_stack_bytes)
  end
  elf_table = elf_table:append(sentinel_bytes)

  local randstraddr
  local cpustraddr
  local execfn
  new_stack = push_str(new_stack, string.rep('a', 16))
  randstraddr = new_stack
  new_stack = push_str(new_stack, 'i686')
  cpustraddr = new_stack
  new_stack = push_str(new_stack, opts.program or "")
  execfn = new_stack

  -- Pushing auxiliary vectors onto stack
  -- See here for explanations: https://lwn.net/Articles/631631/
  local e_phdr = e_phoff + mem_start
  local e_hwcap
  if is_32 then e_hwcap = 0x1fb87d else e_hwcap = 0x078bfbfd end

  local bytes_before_auxv = #elf_table

  elf_table = elf_table:append(arch_bytes(AUXV.AT_HWCAP))
  elf_table = elf_table:append(arch_bytes(e_hwcap))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_PAGESZ))
  elf_table = elf_table:append(arch_bytes(M.mem.PAGESIZE))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_CLKTCK))
  elf_table = elf_table:append(arch_bytes(100))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_PHDR))
  elf_table = elf_table:append(arch_bytes(e_phdr))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_PHENT))
  elf_table = elf_table:append(arch_bytes(e_phentsize))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_PHNUM))
  elf_table = elf_table:append(arch_bytes(e_phnum))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_BASE))
  elf_table = elf_table:append(arch_bytes(addresses.interp_address))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_FLAGS))
  elf_table = elf_table:append(arch_bytes(0))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_ENTRY))
  elf_table = elf_table:append(arch_bytes(entry))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_UID))
  elf_table = elf_table:append(arch_bytes(1000))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_EUID))
  elf_table = elf_table:append(arch_bytes(1000))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_GID))
  elf_table = elf_table:append(arch_bytes(1000))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_EGID))
  elf_table = elf_table:append(arch_bytes(1000))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_SECURE))
  elf_table = elf_table:append(arch_bytes(0))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_RANDOM))
  elf_table = elf_table:append(arch_bytes(randstraddr))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_HWCAP2))
  elf_table = elf_table:append(arch_bytes(0))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_EXECFN))
  elf_table = elf_table:append(arch_bytes(execfn))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_PLATFORM))
  elf_table = elf_table:append(arch_bytes(cpustraddr))
  elf_table = elf_table:append(arch_bytes(AUXV.AT_NULL))
  elf_table = elf_table:append(arch_bytes(0))

  new_stack = M.mem.align(new_stack - #elf_table, 0x10)
  _log.write(string.format("new_stack = %016x", new_stack))
  _log.write(string.format("elf_table size = %04x", #elf_table))

  M.mem.write(new_stack, elf_table)

  res.auxv = new_stack + bytes_before_auxv
  res.stack_pointer = new_stack
  res.load_addr = load_addr
  _log.write(string.format("Stack pointer: %016x", new_stack))

  --TODO: Write vsyscall entries 

  --TODO: setup_procfs()

  --TODO: intercept syscalls, see qiling/os/posix/syscall/

  _log.write("ELF load finish")
  return res
end

return M
