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

local program, stack

program = '/home/john/src/forth/smithforth/SForth'

local env = {
--  [[LD_DEBUG=all]]
--  [[LD_PRELOAD=/usr/local/lib/preload.so]]
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

local _text = 0x10000000
C.ref.label(0x400089, 'binary_interpreter')
C.ref.label(0x400090, 'command')
C.ref.label(0x40009d, 'find1')
C.ref.label(0x4000ac, 'match')
C.ref.label(0x4000b2, 'INPUT')
C.ref.label(0x4000cb, 'HEAD')
C.ref.label(0x10000000, '#IN', { data = true, size = 8, decimal = true, name = '#IN' })
C.ref.label(0x10000008, nil, { data = true, size = 8, ref = true, name = 'TIB' })
C.ref.label(0x10000010, nil, { data = true, size = 8, decimal = true, name = '>IN' })
C.ref.label(0x10000018, nil, { data = true, skip = true, size = 8, name = "" })
C.ref.label(0x10000020, 'STATE', { data = true, size = 8, decimal = true, name = 'STATE' })
C.ref.label(0x10000028, 'LATEST', { data = true, size = 8, ref = true, name = 'LATEST' })

local sforth_refs = {}

local function sforth_disasm_99marker(addr, code, code_offset)
  local size_opts = string.byte(string.sub(code, code_offset + 2, code_offset + 2))
  if size_opts == nil then
    return false
  end
  local immediate = false

  if bit.band(size_opts, 0x60) == 0 then
    local size = bit.band(size_opts, 0x1F)
    local name = string.sub(code, code_offset + 3, code_offset + size + 2)
    local def_addr = addr + size + 2
    C.ref.label(def_addr, '$' ..name)

    local name1 = string.sub(name, 1, 1)
    sforth_refs[name1] = { name = name, addr = def_addr }

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

    local name
    local name_addr = sforth_refs[name1]
    if name_addr == nil then
      name = "!!UNDEFINED!!"
      name_addr = {}
    else
      name = name_addr.name
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
    return true, 2, call_str, name, { hl1, hl2 }, name_addr.addr
  end
end

local function sforth_disasm_forthcall(addr, code, code_offset)
  local cfa = code:i32(code_offset + 3)
  local status, body_str = C.mem.read_safe(cfa, 8)
  if not status then return false end
  local body = body_str:i64()
  local nfa = cfa + 16
  local status, size_opts = C.mem.read_safe(nfa, 1)
  if not status then return false end
  local namelen = bit.band(size_opts:i8(), 0x1f)
  local status, name = C.mem.read_safe(nfa + 1, namelen)
  if not status then return false end

  return true, 7, 'FORTHCALL', string.format("%s (%016x)", name, body), nil, body
end

local function sforth_disasm(addr, code, code_offset)
  local marker = string.byte(string.sub(code, code_offset + 1, code_offset + 1))
  if marker == 0x99 then
    return sforth_disasm_99marker(addr, code, code_offset)
  end

  local m1 = string.byte(string.sub(code, code_offset + 1, code_offset + 1)) or 0
  local m2 = string.byte(string.sub(code, code_offset + 2, code_offset + 2)) or 0
  local m3 = string.byte(string.sub(code, code_offset + 3, code_offset + 3)) or 0

  local is_forthcall = m1 == 0xff and m2 == 0x14 and m3 == 0x25

  if is_forthcall then
    return sforth_disasm_forthcall(addr, code, code_offset)
  end

  return false
end

-- Breakpoints

C.brk.set(0x4000b0) -- Execute immediate (text interpterer)

C.brk.set(0x4000cb, function() -- Head breakpoint on creating header
  local prev_here = C.reg.rdi()
  local here = math.floor((prev_here + 0xf) / 16) * 16

  if prev_here ~= 0 and here > prev_here then
    local gap_size = here - prev_here
    C.ref.label(prev_here, nil, { data = true, skip = true, size = 1, count = gap_size, name = ".align     16" })
  end

  local cfa = here
  local lfa = here + 8
  local nfa = here + 16
  local mask = C.reg.al()
  local namelen = bit.band(mask, 0x1f)
  local addr = nfa + namelen + 1
  local source = C.reg.rsi()
  local name = C.mem.read(source, namelen)

  C.ref.label(addr, name)
  C.ref.label(cfa, nil, { data = true, size = 8, ref = true, name = 'CFA',
    highlight = {
      {
        start_col = 0,
        virt_lines_above = true,
        virt_lines = {
          {
            { string.rep('┈', 43) .. ' ', 'CrcDisComment' },
            { name, 'CrcDisDef' }
          }
        },
      }
    }
  })
  C.ref.label(lfa, nil, { data = true, size = 8, ref = true, name = 'LFA'})

  local immediate = bit.band(mask, 0x80) ~= 0
  local hidden = bit.band(mask, 0x40) ~= 0
  local nfa_text = "NFA        " .. name
  if hidden then nfa_text = nfa_text .. " HIDE" end
  if immediate then nfa_text = nfa_text .. " IMMEDIATE" end
  C.ref.label(nfa, nil, { data = true, size = namelen + 1, count = 1, ref = false, skip = true, name = nfa_text })

  return false -- do not stop
end)

C.dis.maxsize = 833 --TODO: Why maxsize in opts does not work? 
C.dis.dis(dis_buf, elf.entry, #code, { pc = C.reg.pc(), maxsize = 833, disasm_callback = sforth_disasm })

C.dis.maxsize = 90000 --TODO: Why maxsize in opts does not work? 
dis_buf.on_change = function()
  C.reg.dump(reg_buf)
  C.dis.dis(dis_buf_target, 0x10000000, #code, { pc = C.reg.pc(), maxsize = 90000, disasm_callback = sforth_disasm })
end

dis.focus()


dis_buf.go_to_pc()



