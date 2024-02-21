print("Sourced test.caprecon.lua")

local C = require('caprecorn')

C.arch(C.arch.X86_32)
C.engine(C.engine.UNICORN)
C.disasm(C.disasm.CAPSTONE)

C.open()
C.mem.map(0, 2^20)

C.win.begin_layout()

local dump_buf = C.buf.new("Boot dump")
local dump0 = C.win.tab()
dump0.buf(dump_buf)
C.win.end_layout()

local fdesc = io.open('lua/qiling/program.x86.bin')
if fdesc ~= nil then
  print("Executing file")
  local code = fdesc:read(512)
  C.mem.write(0x7c000, code)
  fdesc:close()

  C.hex.dump(dump_buf, 0x07c000, 512)
  --C.dis('Disboot', 0x07c000, code)

  C.start(0x7c000, 2^20)
  C.stop()
  print("Emulation stopped")
else
  print("Faled to open program file!")
end

--C.close()


-- Tests

local function test_open_x86()
end

test_open_x86()
