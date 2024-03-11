--
C = require('caprecorn')
_log = require('_log')
_log.write("LOG STARTED")

C.arch(C.arch.X86_64)
--C.arch(C.arch.AARCH64)
C.engine(C.engine.UNICORN)
C.disasm(C.disasm.CAPSTONE)

_log.write("Before open")
C.open()
--C.mem.map(0x300000, 2^24)

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
C.win.end_layout()

dis_buf.on_change = function()
  C.reg.dump(reg_buf)
  C.reg.dump(vector_reg_buf)
  C.reg.dump(segment_reg_buf)
end

local program, stack, addr, start

--TODO: Tiniest ever ELF https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
--program = '/home/john/src/junk/a.out'
program = '/bin/ls'

local elf = C.elf.loadfile(program)
local code = C.mem.read(elf.mem_start, elf.mem_size)

stack = elf.stack_pointer
start = elf.interp_entry

C.reg.sp(stack)
C.reg.pc(start)

print(string.format("Stack addr = %016x size = %016x", elf.stack_addr, elf.stack_size))
local stack_bytes = C.mem.read(elf.stack_addr, elf.stack_size)
C.hex.dump(dump_buf, elf.stack_addr, #stack_bytes)
dump_bottom.buf(dump_buf)

C.dis.maxsize = 16384 --TODO: Why maxsize in opts does not work? 
C.dis.dis(dis_buf, elf.mem_start, #code, { pc = C.reg.pc(), maxsize = 4096 })

C.reg.dump(reg_buf)
C.reg.dump(vector_reg_buf)
C.reg.dump(segment_reg_buf)

dis.focus()
