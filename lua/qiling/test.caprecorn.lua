print("Sourced test.caprecon.lua")

local C = require('qiling')

local dos = require'os.dos'
print(dos)

local unicorn = require('unicorn')
local const = require('unicorn.unicorn_const')
local cs = require('capstone')

local engine = unicorn.open(const.UC_ARCH_X86, const.UC_MODE_32)
engine:mem_map(0, 2^20)

local fdesc = io.open('lua/qiling/program.x86.bin')
if fdesc ~= nil then
  print("Executing file")
  local code = fdesc:read(512)
  --pcall(function() engine:mem_write(0x7c000, code) end)
  if 1 == 2 then
  fdesc:close()
  C.hex('Boot', 0x07c000, code)
  C.dis('Disboot', 0x07c000, code)

  engine:emu_start(0x7c000, 2^20)
  engine:emu_stop()
  print("Emulation stopped")
  end
else
  print("Faled to open program file!")
end

engine:close()

