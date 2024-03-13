# TODO

## Caprecorn

### Organisational

- Find interesting/obfuscated malware samples or CTF challenges (see links in [CTF.md])

### Core

+ Hook each instruction and write trace and compare
- Hook RDTSC to provide deterministic results (w/a sequential execution? Need exact tick counts)

- Lua 5.1 does not work properly with 64-bit integers. Maybe return them as two 32-bit integers when needed? Implement i64 class?
  See https://github.com/cloudwu/lua-int64, also 
  Actually, we need only 48 bits for addresses, and sign-extend, if needed (LuaJIT and Lua 5.1 should support 53-bit integers precisely)
  For register values, 2 32-bit integers can be returned and handled properly
  unicorn-lua probably needs to be modified to support this
+ How does Unicorn/Qemu execute SYSCALL w/o emulation or hooks? 
+ Rename from Qiling to Caprecorn. Or Qrx
+ Buf module for buffers: hex, dis, map, reg, stack...
+ Do not expose Unicorn and Capstone, provide access via Caprecorn
+ Mapping between Unicorn and Capstone registers
- Allow multiple hooks (including internal and user-defined)
- Allow NVim-less scripting for debugging or standalone (if vim ~= nil then...)
+ For start/stop/mem and other functions add stubs that error if used before initialization

### UI

+ pcall when trying to close a window that might have been closed by a user
* Think about session support (check if a "marker" buffer exists and thus assume a session has been open)
  Should be handled transparently for a user. New buffers can be created. New windows should be created (how?)
  For now, buffers and windows are closed on reload ('LL' command)
* Add a possibility to create windows in current tab, w/o creating a new one (maybe someone would want this)
+ Highlights
- Log window
- Window parameter: adjust width to buffer text width, or wrap text
- Focus window before splitting, otherwise you split the last created window (focus should be window method, not just a function)
- Help for each buffer (popup windows?)
- Go to address: enter <address[,size|,,end_address] | +/-offset>  
- Multiple buffers for single window
- Show memory maps
- Stack view (RSP + and - offsets)
- Hook sample (1032.bin): starting this point stop when RAX = 0x29
- When stepping into a call in another window show where the subtoutine will return (can be done manually, but boring)
- Step back with restoring registers (memory can come later)
- Flags display and show if a conditional jump will be executed
- Compute effective address. Show dump if it is a memory operation or disassemble if this is an indirect jump/call 
- Display memory maps. Go to hex dump from maps view

## Capstone

- When using EIP/RIP-relative addressing, add an option to show effective address in disassembly instead of offset from EIP/RIP

## LuaCapstone

- Crash on freeiterator(). Propably it uses wrong parameter index (2 instead of 1)

## Qiling

- Continue Qiling support via PyNvim
  #NVIM_LISTEN_ADDRESS=/tmp/nvim nvim -S Session.vim +"set rtp+=$(pwd)"
- Bi-directional communication (w/a thread safety?)

## Unicorn

+ Self-modified code conflicts with instruction counter. See tb_invalidate_phys_page_range__locked in translate-all.c
- Reading CR8 register crashes

## Unicorn-Lua

* Replace throw's() in Lua callable functions with error codes 
  (since Lua has C API, not C++ API, and exceptions crash the whole process)

# TO SEE

https://github.com/ampotos/dynStruct
DynamoRIO

Also OllyDbg, x86dbg 

# TO PLAY/EXPLORE

- Forth in AVX-2 (?)
- Can code segment be only executable and not readable?

