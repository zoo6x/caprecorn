# TODO

## Caprecorn

- Rename from Qiling to Caprecorn
- Buf module for buffers: hex, dis, map, reg, stack...
- Help for each buffer
- Do not expose Unicorn and Capstone, provide access via Caprecorn
- Mapping between Unicorn and Capstone registers
- Allow multiple hooks (including internal and user-defined)
- Allow NVim-less scripting for debugging or standalone (if vim ~= nil then...)
- For start/stop/mem and other functions add stubs that error if used before initialization

## Capstone

- Crash on freeiterator()

## Qiling

- Continue Qiling support via PyNvim
- Bi-directional communication (w/a thread safety?)

## Unicorn-Lua

- Replace throw's() in Lua callable functions with error codes 
  (since Lua has C API, not C++ API, and exceptions crash the whole process)
