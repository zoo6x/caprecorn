--
C = require('caprecorn')
_log = require('_log')

C.arch(C.arch.X86_64)
C.engine(C.engine.UNICORN)
C.disasm(C.disasm.CAPSTONE)

C.open()

-- Creating windows
C.win.begin_layout()

local dump = C.win.tab()

local dump_buf = C.buf.new("Boot dump")
local dis_buf = C.buf.new("Boot disassembly")
local dis_buf_target = C.buf.new("Target disassembly")
local reg_buf = C.buf.new("Regs")
reg_buf.opts = {
  show_flags = true,
  filter = { base = false, vector = false, segment = false, fp = false, system = false, }
}
local vector_reg_buf = C.buf.new("Vector Regs")
vector_reg_buf.opts = {
  filter = { base = false, vector = true, }
}

local total_width = dump.width()
local dis = dump.vsplit()
local dump_bottom = dis.split()
dump_bottom.height(10)
dis.width(math.floor(total_width * 0.8))
dump.focus()
local reg = dump.split()
dis.buf(dis_buf)
reg.buf(reg_buf)
C.win.end_layout()

-- Creating buffers

local code

dis_buf.on_change = function()
  C.reg.dump(reg_buf)
  C.dis.dis(dis_buf_target, 0x10000000, #code, { pc = C.reg.pc(), maxsize = 90000 })
end

local program, stack

program = '/home/john/src/forth/smithforth/SForth'

local env = {
--  [[LD_DEBUG=all]]
  [[LD_PRELOAD=/usr/local/lib/preload.so]]
}

local elf = C.elf.loadfile(program, {
--    argv = { program, "flag" },
    env = env,
  })

code = C.mem.read(elf.entry, 0x4000)

stack = elf.stack_pointer

C.reg.pc(elf.entry)
C.reg.sp(stack)

local stack_bytes = C.mem.read(elf.stack_addr, elf.stack_size)
C.hex.dump(dump_buf, 0x4000b2, 4096)
dump_bottom.buf(dump_buf)

C.reg.dump(reg_buf)
C.reg.dump(vector_reg_buf)

C.ref.label(0x400089, 'binary_interpreter')
C.ref.label(0x400090, 'command')
C.ref.label(0x40009d, 'find1')
C.ref.label(0x4000ac, 'match')
C.ref.label(0x4000b2, 'INPUT')
C.ref.label(0x4000cb, 'HEAD')
C.ref.label(0x10000000, nil, { data = true, size = 8, decimal = true, name = '#IN' })
C.ref.label(0x10000008, nil, { data = true, size = 8, ref = true, name = 'TIB' })
C.ref.label(0x10000010, nil, { data = true, size = 8, decimal = true, name = '>IN' })
C.ref.label(0x10000018, nil, { data = true, skip = true, size = 8, name = "" })
C.ref.label(0x10000020, 'STATE', { data = true, size = 8, decimal = true, name = 'STATE' })
C.ref.label(0x10000028, 'LATEST', { data = true, size = 8, ref = true, name = 'LATEST' })
C.ref.label(0x10000030, 'TEXT')

local sforth_refs = {}

local function sforth_disasm(addr, code, code_offset)
  local marker = string.byte(string.sub(code, code_offset + 1, code_offset + 1))
  if marker ~= 0x99 then
    return false
  end
  local size_opts = string.byte(string.sub(code, code_offset + 2, code_offset + 2))
  if size_opts == nil then
    return false
  end
  local immediate = false

  if bit.band(size_opts, 0x60) == 0 then
    local size = bit.band(size_opts, 0x1F)
    local name = string.sub(code, code_offset + 3, code_offset + size + 2)
    local def_addr = addr + size + 2
    C.ref.label(def_addr, name)

    local name1 = string.sub(name, 1, 1)
    sforth_refs[name1] = name

    local hl1 = {
      start_col = 44,
      end_col = 54,
      hl_group = 'CrcDisSymbol',
    }
    local hl2 = {
      start_col = 55,
      end_col = 999,
      hl_group = 'CrcDisDef',
    }

    return true, size + 2, ":", name, { hl1, hl2 }
  else
    local name1 = string.sub(code, code_offset + 2, code_offset + 2)
    local marker = string.byte(string.sub(name1, 1, 1))
    if bit.band(marker, 0x80) == 0x80 then
      immediate = true
      name1 = string.char(bit.band(marker, 0x7F))
    end

    local name = sforth_refs[name1]
    if name == nil then
      name = "!!UNDEFINED!!"
    end

    local hl1 = {
      start_col = 44,
      end_col = 54,
      hl_group = 'CrcDisCall',
    }
    local hl2 = {
      start_col = 55,
      end_col = 999,
      hl_group = 'CrcDisTarget',
    }
    local call_str
    if immediate then
      call_str = 'FORTHEXEC'
    else
      call_str = 'FORTHCALL'
    end
    return true, 2, call_str, name, { hl1, hl2 }
  end
end

C.brk.set(0x4000b0) -- Execute immediate (text interpterer)
local prev_here = 0

--TODO: Setting breakpoint at 0x4000cb fires only twice! Why?
C.brk.set(0x4000cf, function()
  prev_here = C.reg.rdi()
  prev_here = prev_here - 0xf
  _log.write(string.format("prev_here=%016x", prev_here))
  return false
end)

C.brk.set(0x4000dd, function() -- Head breakpoint on creating header
  local here = C.reg.rdi()
  _log.write(string.format("here=%016x", here))

  if prev_here ~= 0 and here > prev_here then
    local gap_size = here - prev_here
    _log.write(string.format("prev_here=%016x here=%016x gap=%d", prev_here, here, gap_size))
    C.ref.label(prev_here, nil, { data = true, skip = true, size = 1, count = gap_size })
  end

  local cfa = here
  local lfa = here + 8
  local nfa = here + 16
  local mask = C.reg.al()
  local namelen = bit.band(mask, 0x1F)
  local addr = nfa + namelen + 1
  local source = C.reg.rsi()
  local name = C.mem.read(source, namelen)

  C.ref.label(addr, name)
  C.ref.label(cfa, nil, { data = true, size = 8, ref = true, name = 'CFA'})
  C.ref.label(lfa, nil, { data = true, size = 8, ref = true, name = 'LFA'})
  C.ref.label(nfa, nil, { data = true, size = 1, count = namelen + 1, ref = true, name = 'NFA'})

  _log.write(string.format("address = %016x name=[%s]", addr, name))

  return false -- do not stop
end)

C.dis.maxsize = 833 --TODO: Why maxsize in opts does not work? 
C.dis.dis(dis_buf, elf.entry, #code, { pc = C.reg.pc(), maxsize = 833, disasm_callback = sforth_disasm })

C.dis.maxsize = 90000 --TODO: Why maxsize in opts does not work? 
C.dis.dis(dis_buf_target, 0x10000000, #code, { pc = C.reg.pc(), maxsize = 90000 })

dis.focus()


dis_buf.go_to_pc()



