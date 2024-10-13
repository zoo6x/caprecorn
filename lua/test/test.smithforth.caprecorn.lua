--
C = require('caprecorn')
_log = require('_log')

C.arch(C.arch.X86_64)
--C.arch(C.arch.AARCH64)
C.engine(C.engine.UNICORN)
C.disasm(C.disasm.CAPSTONE)

C.open()
_log.write("Before mmap")
C.mem.map(0x555555550000, 0x100000)
_log.write("After mmap")

C.win.begin_layout()

local dump = C.win.tab()

local dump_buf = C.buf.new("Boot dump")
local dis_buf = C.buf.new("Boot disassembly")
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

dis_buf.on_change = function()
  C.reg.dump(reg_buf)
end

local program, stack, addr, start, size

program = '/home/john/src/forth/smithforth/SForth'
stack = 0x555555553000
addr  = 0x555555554000
start = 0x555555555120
size = 65536

local env = {
--  [[LD_DEBUG=all]]
  [[LD_PRELOAD=/usr/local/lib/preload.so]]
}

local elf = C.elf.loadfile(program,
  {
    argv = { program, "flag" },
    env = env,
    rootfs = "/home/john/src/qiling-dev/examples/rootfs/x8664_linux_latest",
  })


local code = C.mem.read(elf.mem_start, 0x4000)

stack = elf.stack_pointer
start = elf.interp_entry

C.reg.sp(stack)
C.reg.pc(start)

local stack_bytes = C.mem.read(elf.stack_addr, elf.stack_size)
C.hex.dump(dump_buf, elf.stack_addr, 4096)
dump_bottom.buf(dump_buf)

C.dis.maxsize = 16384 --TODO: Why maxsize in opts does not work? 
C.dis.dis(dis_buf, elf.mem_start, #code, { pc = C.reg.pc(), maxsize = 4096 })

C.reg.dump(reg_buf)
C.reg.dump(vector_reg_buf)

local flags = C.reg.flags()
local Z = C.flag.ZERO
local flag_Z = C.reg.flag(C.flag.ZERO)
local flag_C = C.reg.flag(C.flag.CARRY)
C.reg.flag(C.flag.ZERO, true)
local flag_Z2 = C.reg.flag(C.flag.ZERO)
local flags2 = C.reg.flags()
print("Flags Z C Z' flags=", flags, flag_Z, flag_C, flag_Z2, flags2)

dis.focus()

_log.write("Running program till entry...")
if elf.interp_entry ~= nil then
  C.emu.set_breakpoints({ elf.entry })
  C.unstop()
  local res, status = C.start(C.reg.pc(), -1, 0, 0)
  C.emu.stop() -- Ugly, to fix
  if not res then
    _log.write(string.format("Error at PC=%016x [%s]", C.reg.pc(), status))
  else
    _log.write(string.format("Stopped at PC=%016x", C.reg.pc()))
  end
  _log.write(string.format("Program PC=%016x", elf.entry))
else
  C.reg.pc(elf.entry)
end
dis_buf.go_to_pc()



