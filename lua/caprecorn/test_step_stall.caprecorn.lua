C = require('caprecorn')

C.arch(C.arch.X86_64)
C.engine(C.engine.UNICORN)
C.disasm(C.disasm.CAPSTONE)

C.open()
C.mem.map(0, 2^24)

C.win.begin_layout()

local dump_buf = C.buf.new("Boot dump")
local dis_buf = C.buf.new("Boot disassembly")
local reg_buf = C.buf.new("Registers")

local dump = C.win.tab()
local dis = dump.vsplit()
dump.focus()
local reg = dump.split()
dis.buf(dis_buf)
reg.buf(reg_buf)
C.win.end_layout()

dis_buf.on_change = function()
  C.reg.dump(reg_buf)
end

local program, stack, addr, start, size
stack = 0x0
-- TODO: Why does not run with address 0?
-- Also see this issue https://github.com/unicorn-engine/unicorn/issues/1846
-- When stepping 2 instructions, all works. Workaround for now?
addr = 0x000000
start = 0x000000

  local bytes = {
    -- 0x48, 0xc7, 0xc2, 0x10, 0x00, 0x40, 0x00,
    -- 0x48, 0xc7, 0xc2, 0x00, 0x00, 0x00, 0x00,
    -- 0x48, 0x31, 0xd2,
    -- 0xbf, 0x01, 0x00, 0x00, 0x00, -- mov rdi, xxxx
    -- 0x90, -- adding this NOP prolongs execution till much longer
    0x33, 0x18,
    0x31, 0x00,
    0x31, 0x00,
    0x31, 0x00,
    0x31, 0x00,
    0xff, 0xc1,
    -- 0x31, 0x52, 0x00, -- any offset from 4 to 3B hangs 
    -- 0x90,
  --[[
    0x31, 0xba, 0x04, 0x00, 0x00, 0x00,
    0x31, 0x7a, 0x01,
    0x31, 0x7a, 0x08,
    0x31, 0x7a, 0x0d,
    0x31, 0x7a, 0x10,
    0x11, 0x7a, 0x20,
    0x09, 0x7a, 0x30,
    0x31, 0x7a, 0x40,
    0x31, 0x7a, 0x50,
    0x31, 0x7a, 0x60,
    0x31, 0x7a, 0x70,
    0x31, 0x7a, 0x7f,
  ]]
    0xeb, 0xfa,
  }
size = #bytes

  local code = ""
  for i = 1, #bytes do
    code = code .. string.char(bytes[i])
  end

  C.mem.write(addr, code)

  C.hex.dump(dump_buf, addr, #code)
  dump.buf(dump_buf)
  C.dis.maxsize = size
  C.dis.dis(dis_buf, start, #code)

  C.reg.sp(stack)
  C.reg.pc(start)
  C.reg.dump(reg_buf)

  dis.focus()

