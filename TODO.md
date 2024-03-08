# TODO

## Caprecorn

### Core

- Lua 5.1 does not work properly with 64-bit integers. Maybe return them as two 32-bit integers when needed? Implement i64 class?
- How does Unicorn/Qemu execute SYSCALL w/o emulation or hooks? 
+ Rename from Qiling to Caprecorn. Or Qrx
+ Buf module for buffers: hex, dis, map, reg, stack...
+ Do not expose Unicorn and Capstone, provide access via Caprecorn
- Mapping between Unicorn and Capstone registers
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

## Capstone

- When using EIP/RIP-relative addressing, add an option to show effective address in disassembly instead of offset from EIP/RIP

## LuaCapstone

- Crash on freeiterator(). Propably it uses wrong parameter index (2 instead of 1)

## Qiling

- Continue Qiling support via PyNvim
- Bi-directional communication (w/a thread safety?)

## Unicorn

- Self-modified code conflicts with instruction counter. See tb_invalidate_phys_page_range__locked in translate-all.c

## Unicorn-Lua

* Replace throw's() in Lua callable functions with error codes 
  (since Lua has C API, not C++ API, and exceptions crash the whole process)

# TO SEE

https://github.com/ampotos/dynStruct
DynamoRIO

Also OllyDbg, x86dbg 
