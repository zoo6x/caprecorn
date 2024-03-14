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
  [[BASH=/usr/bin/bash]],
  [[BASHOPTS=checkwinsize:cmdhist:complete_fullquote:expand_aliases:extglob:extquote:force_fignore:globasciiranges:histappend:interactive_comments:progcomp:promptvars:sourcepath]],
  "BASH_ALIASES=()",
  [[BASH_ARGC=([0]="0")]],
  [[BASH_ARGV=()]],
  [[BASH_CMDS=()]],
  [[BASH_COMPLETION_VERSINFO=([0]="2" [1]="10")]],
  [[BASH_LINENO=()]],
  [[BASH_REMATCH=()]],
  [[BASH_SOURCE=()]],
  [[BASH_VERSINFO=([0]="5" [1]="0" [2]="17" [3]="1" [4]="release" [5]="x86_64-pc-linux-gnu")]],
  [[BASH_VERSION='5.0.17(1)-release']],
  [[COLORTERM=truecolor]],
  [[COLUMNS=305]],
  [[COMP_WORDBREAKS=$' \t\n"\'><=;|&(:']],
  [[DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus]],
  [[DESKTOP_SESSION=ubuntu]],
  [[DIRSTACK=()]],
  [[DISPLAY=:0]],
  [[EUID=1001]],
  [[GDMSESSION=ubuntu]],
  [[GJS_DEBUG_OUTPUT=stderr]],
  [[GJS_DEBUG_TOPICS='JS ERROR;JS LOG']],
  [[GNOME_DESKTOP_SESSION_ID=this-is-deprecated]],
  [[GNOME_SHELL_SESSION_MODE=ubuntu]],
  [[GNOME_TERMINAL_SCREEN=/org/gnome/Terminal/screen/8772aea9_2152_4fb4_92a8_3c63ddd1ad5c]],
  [[GNOME_TERMINAL_SERVICE=:1.169]],
  [[GPG_AGENT_INFO=/run/user/1001/gnupg/S.gpg-agent:0:1]],
  [[GREP_COLORS='ms=01;32:mc=01;31:sl=:cx=:fn=35:ln=32:bn=32:se=36']],
  [[GROUPS=()]],
  [[GTK_MODULES=gail:atk-bridge]],
  [[HISTCONTROL=ignoreboth]],
  [[HISTFILE=/home/john/.bash_history]],
  [[HISTFILESIZE=2000]],
  [[HISTSIZE=1000]],
  [[HOME=/home/john]],
  [[HOSTNAME=GroundStation-15]],
  [[HOSTTYPE=x86_64]],
  [[IFS=$' \t\n']],
  [[IM_CONFIG_PHASE=1]],
  [[INVOCATION_ID=ceff31113362465fb5f665f9c37cd8a7]],
  [[JOURNAL_STREAM=8:45648]],
  [[LANG=en_US.UTF-8]],
  [[LC_ADDRESS=uk_UA.UTF-8]],
  [[LC_IDENTIFICATION=uk_UA.UTF-8]],
  [[LC_MEASUREMENT=uk_UA.UTF-8]],
  [[LC_MONETARY=uk_UA.UTF-8]],
  [[LC_NAME=uk_UA.UTF-8]],
  [[LC_NUMERIC=uk_UA.UTF-8]],
  [[LC_PAPER=uk_UA.UTF-8]],
  [[LC_TELEPHONE=uk_UA.UTF-8]],
  [[LC_TIME=uk_UA.UTF-8]],
  [[LESSCLOSE='/usr/bin/lesspipe %s %s']],
  [[LESSOPEN='| /usr/bin/lesspipe %s']],
  [[LINES=80]],
  [[LOGNAME=john]],
  [[MACHTYPE=x86_64-pc-linux-gnu]],
  [[MAILCHECK=60]],
  [[MANAGERPID=1390]],
  [[OLDPWD=/home/john]],
  [[OPTERR=1]],
  [[OPTIND=1]],
  [[OSTYPE=linux-gnu]],
  [[PATH=/home/john/.local/bin:/home/john/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin]],
  [[PIPESTATUS=([0]="0")]],
  [[PPID=9914]],
  [[PS1='\[\e]0;\u@\h: \w\a\]${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ ']],
  [[PS2='> ']],
  [[PS4='+ ']],
  [[PWD=/home/john/src/junk]],
  [[QT_ACCESSIBILITY=1]],
  [[QT_IM_MODULE=ibus]],
  [[SESSION_MANAGER=local/GroundStation-15:@/tmp/.ICE-unix/1526,unix/GroundStation-15:/tmp/.ICE-unix/1526]],
  [[SHELL=/bin/bash]],
  [[SHELLOPTS=braceexpand:emacs:hashall:histexpand:history:interactive-comments:monitor]],
  [[SHLVL=1]],
  [[SSH_AGENT_PID=1488]],
  [[SSH_AUTH_SOCK=/run/user/1001/keyring/ssh]],
  [[TERM=xterm-256color]],
  [[UID=1001]],
  [[USER=john]],
  [[USERNAME=john]],
  [[VTE_VERSION=6003]],
  [[WINDOWPATH=2]],
  [[XAUTHORITY=/run/user/1001/gdm/Xauthority]],
  [[XDG_CONFIG_DIRS=/etc/xdg/xdg-ubuntu:/etc/xdg]],
  [[XDG_CURRENT_DESKTOP=ubuntu:GNOME]],
  [[XDG_DATA_DIRS=/usr/share/ubuntu:/usr/local/share/:/usr/share/:/var/lib/snapd/desktop]],
  [[XDG_MENU_PREFIX=gnome-]],
  [[XDG_RUNTIME_DIR=/run/user/1001]],
  [[XDG_SESSION_CLASS=user]],
  [[XDG_SESSION_DESKTOP=ubuntu]],
  [[XDG_SESSION_TYPE=x11]],
  [[XMODIFIERS=@im=ibus]],
}

local elf = C.elf.loadfile(program, { argv = { program }, env = env })

-- C.emu.set_breakpoints({ 0x00007ffff7df3d37, 0x00007ffff7df3d39 })

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
