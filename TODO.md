# TODO

## Caprecorn

### Core

+ Rename from Qiling to Caprecorn
+ Buf module for buffers: hex, dis, map, reg, stack...
+ Do not expose Unicorn and Capstone, provide access via Caprecorn
- Mapping between Unicorn and Capstone registers
- Allow multiple hooks (including internal and user-defined)
- Allow NVim-less scripting for debugging or standalone (if vim ~= nil then...)
- For start/stop/mem and other functions add stubs that error if used before initialization

### UI

+ pcall when trying to close a window that might have been closed by a user
- Think about session support (check if a "marker" buffer exists and thus assume a session has been open)
  Should be handled transparently for a user. New buffers can be created. New windows should be created (how?)
* Add a possibility to create windows in current tab, w/o creating a new one (maybe someone would want this)
- Highlights
- Log window
- Window parameter: adjust width to buffer text width, or wrap text
- Focus window before splitting, otherwise you split the last created window (focus should be window method, not just a function)
- Help for each buffer (popup windows?)
- Hex Go to address: enter <address[,size|,,end_address] | +/-offset>  
- Autowidth option for windows (change window width on buffer update or when buffer is assigned to a window)
- Multiple buffers for single window
- Show memory maps

## Capstone

- Crash on freeiterator(). Propably it user wrong parameter index (2 instead of 1)

## Qiling

- Continue Qiling support via PyNvim
- Bi-directional communication (w/a thread safety?)

## Unicorn-Lua

* Replace throw's() in Lua callable functions with error codes 
  (since Lua has C API, not C++ API, and exceptions crash the whole process)
