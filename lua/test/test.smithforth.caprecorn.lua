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


local code = C.mem.read(elf.entry, 0x4000)

stack = elf.stack_pointer
start = elf.interp_entry

C.reg.sp(stack)
C.reg.pc(start)

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
C.ref.label(0x10000028, 'LATEST')
C.ref.label(0x10000030, 'HERE')

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

  if bit.band(size_opts, 0x60) == 0 then
    local size = bit.band(size_opts, 0x1F)
    local name = string.sub(code, code_offset + 3, code_offset + size + 2)
    local def_addr = addr + size + 2
    C.ref.label(def_addr, name)

    local name1 = string.sub(name, 1, 1)
    sforth_refs[name1] = name

    return true, size + 2, ":", name
  else
    local name1 = string.sub(code, code_offset + 2, code_offset + 2)
    local name = sforth_refs[name1]
    if name == nil then
      name = "!!UNDEFINED!!"
    end
    return true, 2, "CALL", name
  end
end

C.dis.maxsize = 833 --TODO: Why maxsize in opts does not work? 
C.dis.dis(dis_buf, elf.entry, #code, { pc = C.reg.pc(), maxsize = 833, disasm_callback = sforth_disasm })

dis.focus()

C.reg.pc(elf.entry)

dis_buf.go_to_pc()



