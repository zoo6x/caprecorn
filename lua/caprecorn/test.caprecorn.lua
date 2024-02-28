print("Sourced test.caprecon.lua")

local C = require('caprecorn')

C.arch(C.arch.X86_64)
C.engine(C.engine.UNICORN)
C.disasm(C.disasm.CAPSTONE)

C.open()
C.mem.map(0, 2^24)

C.win.begin_layout()

local dump_buf = C.buf.new("Boot dump")
local dis_buf = C.buf.new("Boot disassembly")
local dump = C.win.tab()
local dis = dump.vsplit()
dis.buf(dis_buf)
C.win.end_layout()

local program, addr, size
-- program = 'lua/qiling/program.x86.bin'
-- addr = 0x07c000
-- size = 512
program = '/bin/ls'
addr = 0x400000
size = 142144

local fdesc = io.open(program)
if fdesc ~= nil then
  print("Executing file")
  local code = fdesc:read(size)
  C.mem.write(addr, code)
  fdesc:close()

  C.hex.dump(dump_buf, addr, #code)
  --dump.buf(dump_buf)
  C.dis.maxsize = size
  C.dis.dis(dis_buf, addr, #code)

  --C.start(0x7c000, 2^20)
  C.stop()
--  print("Emulation stopped")
else
  print("Faled to open program file!")
end

--C.close()


-- Tests

local function test_open_x86()
end

test_open_x86()
