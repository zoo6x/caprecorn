--
-- Article about PLT and GOT structure
-- https://gist.github.com/x0nu11byt3/bcb35c3de461e5fb66173071a2379779
-- https://github.com/kubo/plthook
-- https://stackoverflow.com/questions/62611218/parse-plt-stub-addresses-and-names
--
-- Text segment can be identified as a LOAD segment with EXECUTE protection
-- Then figure out PLT structure...


C = require('caprecorn')

local _log = require('_log')
_log.write("LOG STARTED")

C.arch(C.arch.X86_64)
--C.arch(C.arch.AARCH64)
C.engine(C.engine.UNICORN)
C.disasm(C.disasm.CAPSTONE)

_log.write("Before open")
C.open()

C.win.begin_layout()

local dump = C.win.tab()

local dump_buf = C.buf.new("Dump")
local gdt_dump_buf = C.buf.new("GDT")
C.hex.dump(gdt_dump_buf, 0x30000, 16*8, { width = 8, show_chars = false, })
local dis_buf = C.buf.new("Disassembly")
local reg_buf = C.buf.new("Regs")
reg_buf.opts = {
  filter = { base = false, vector = false, segment = false, fp = false, system = false, }
}
local vector_reg_buf = C.buf.new("Vector Regs")
vector_reg_buf.opts = {
  filter = { base = false, vector = true, }
}
local segment_reg_buf = C.buf.new("Segment Regs")
segment_reg_buf.opts = {
  filter = { segment = true, }
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

local log_tab = C.win.tab()
vim.cmd[[e ./caprecorn.log]]

C.win.end_layout()

dis_buf.on_change = function()
  C.reg.dump(reg_buf)
  C.reg.dump(vector_reg_buf)
  C.reg.dump(segment_reg_buf)

  dump_buf:dump()
end

local program, stack, addr, start

--TODO: Tiniest ever ELF https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
program = '/home/john/bin/malware/2/level3'
-- program = '/home/john/src/junk/stat'
-- program = '/bin/ls'

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

-- C.emu.set_breakpoints({ elf.entry, 0x0000555555555454, 0x000055555555549e })
C.emu.set_breakpoints({ elf.entry })

local code = C.mem.read(elf.mem_start, 0x4000)

stack = elf.stack_pointer
start = elf.interp_entry

C.reg.sp(stack)
_log.write(string.format("Start = %016x", start))
C.reg.pc(start)

print(string.format("Stack addr = %016x size = %016x", elf.stack_addr, elf.stack_size))
local stack_bytes = C.mem.read(elf.stack_addr, elf.stack_size)
C.hex.dump(dump_buf, elf.stack_addr, 4096)
dump_bottom.buf(dump_buf)

C.dis.maxsize = 16384 --TODO: Why maxsize in opts does not work? 
C.dis.dis(dis_buf, elf.mem_start, #code, { pc = C.reg.pc(), maxsize = 4096 })

C.reg.dump(reg_buf)
C.reg.dump(vector_reg_buf)
C.reg.dump(segment_reg_buf)

dis.focus()

_log.write("Running program till entry...")
C.unstop()
local res, status = C.start(C.reg.pc(), -1, 0, 0)
C.emu.stop() -- Ugly, to fix
if not res then
  _log.write(string.format("Error at PC=%016x [%s]", C.reg.pc(), status))
else
  _log.write(string.format("Stopped at PC=%016x", C.reg.pc()))
end
_log.write(string.format("Program PC=%016x", elf.entry))

dis_buf.go_to_pc()

