--

-- Can mapped areas overlap if they have different protections?
--[[
MEMORY MAP address = 0000000000030000 - 0000000000031000 size = 1000
MEMORY MAP address = 00007ffffffde000 - 000080000000e000 size = 30000
MEMORY MAP address = 0000000000400000 - 0000000000401000 size = 1000
MEMORY MAP address = 0000000000401000 - 0000000000402000 size = 1000
MEMORY MAP address = 0000000000402000 - 0000000000403000 size = 1000
MEMORY MAP address = 0000000000403000 - 0000000000405000 size = 2000
MEMORY MAP address = 00007ffff7dd5000 - 00007ffff7dd6000 size = 1000
MEMORY MAP address = 00007ffff7dd6000 - 00007ffff7df9000 size = 23000
MEMORY MAP address = 00007ffff7df9000 - 00007ffff7e01000 size = 8000
MEMORY MAP address = 00007ffff7e02000 - 00007ffff7e05000 size = 3000
MEMORY MAP address = 00007fffb7db1000 - 00007fffb7dd6000 size = 25000
MEMORY MAP address = 00007fffb7bbf000 - 00007fffb7db1000 size = 1f2000
MEMORY MAP address = 00007fffb7be1000 - 00007fffb7d59000 size = 178000

]]


-- Catch all writes to this area? Certain address?
-- Map 0x2000 at   0x00007fffb7dc7000 
-- Damaged name at 0x00007fffb7dc70c0
-- How to debug it? 
-- Stop after syscall with certain parameters, w/o stepping back?
-- I.e., stop after a successful syscall execution
-- Implement fstat() before this ?
-- Or:
--  - Turn off ASRL
--  - Make sure Linux, Qiling and we mmap at the same addresses
--  - Integrate with Qiling and compare memory and registers

C = require('caprecorn')

local _log = require('_log')
_log.write("LOG STARTED")

C.arch(C.arch.X86_64)
--C.arch(C.arch.AARCH64)
C.engine(C.engine.UNICORN)
C.disasm(C.disasm.CAPSTONE)

_log.write("Before open")
C.open()

C.mem.map(0x50000, 0x10000)
C.mem.unmap(0x51000, 0x0f000)


C.win.begin_layout()

local dump = C.win.tab()

local dump_buf = C.buf.new("Dump")
local gdt_dump_buf = C.buf.new("GDT")
C.hex.dump(gdt_dump_buf, 0x30000, 16*8, { width = 8, show_chars = false, })
local dis_buf = C.buf.new("Disassembly")
local reg_buf = C.buf.new("Regs")
reg_buf.opts = {
  filter = { base = false, flags = false, vector = false, segment = false, fp = false, system = false, }
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
end

local program, stack, addr, start

--TODO: Tiniest ever ELF https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
program = '/home/john/src/junk/stat'
-- program = '/bin/ls'

local env = {
  [[LD_DEBUG=all]]
}

local elf = C.elf.loadfile(program, 
  { 
    argv = { program }, 
    env = env,
    rootfs = "/home/john/src/qiling-dev/examples/rootfs/x8664_linux_latest",
  })

--C.emu.set_breakpoints({ 0x00007ffff7ff7aa4 })

local code = C.mem.read(elf.mem_start, 0x4000)

stack = elf.stack_pointer
start = elf.interp_entry

C.reg.sp(stack)
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
