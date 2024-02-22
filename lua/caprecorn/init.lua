local M = {}

-- Supported architectures
local arch = require("arch")
M.arch = arch.arch

setmetatable(M.arch, { __call = function(_, _arch)
  M._arch = _arch
end})

-- Memory access interface
-- Is set up by the engine
M.mem = {}

-- Supported emulation engines
M.engine = {}
M.engine.UNICORN = "UNICORN"
M.engine.QILING = "QILING"

setmetatable(M.engine, { __call = function (_, engine)
  print("Engine=", engine)
  if M.engine[engine] ~= nil then
    M.__engine = engine
  else
    error(string.format("Unknown emulation engine=[%s]", engine))
  end

  if engine == M.engine.UNICORN then
    local _unicorn = require("_unicorn")

    M.open = function()
      --TODO: error checks, tests (including invalid parameters)
      --TODO: separate Unicorn and Capstone
      _unicorn.open(M._arch)
      M._engine = _unicorn.engine
      M._disasm = _unicorn.disasm
    end

    local prev_close = M.close
    M.close = function()
      if prev_close ~=nil then
        prev_close()
      end
      _unicorn.close()
    end

    M.start = function(from, to)
      M._engine:emu_start(from, to)
    end

    M.stop = function()
      M._engine:emu_stop()
    end

    M.mem.map = function(from, size)
      M._engine:mem_map(from, size)
    end

    M.mem.read = function(from, size)
      local status, bytes_or_message = M._engine:mem_read(from, size)

      if not status then
        error(string.format("Error [%s] when trying to read %d bytes from address 0x%x", bytes_or_message, size, from))
      end

      return bytes_or_message
    end

    M.mem.write = function(from, bytes)
      M._engine:mem_write(from, bytes)
    end

    -- Disassembler

    local capstone = require("capstone")

    M.disasm.createiterator = function(from, code)
      local it = capstone.createiterator(M._disasm, code, #code, from)

      return it
    end

    M.disasm.disasmiter = function(it)
      return capstone.disasmiter(M._disasm, it)
    end

    M.disasm.freeiterator = function(it)
      --TODO: Fix in C++ LuaCapstone
      -- capstone.freeiterator(it)
    end

  end
end})

-- Supported disassemblers
M.disasm = {}
M.disasm.CAPSTONE = "CAPSTONE"

M.__disasm = M.disasm.CAPSTONE

setmetatable(M.disasm, { __call = function(_, disasm)
  if M.disasm[disasm] ~= nil then
    M._disasm = disasm
  else
    error(string.format("Unknown disassembler disasm=[%s]", disasm))
  end
end})

-- Vim UI integration
M.buf = require("buf")
M.win = require("win")

M.close = function()
  M.win.close()
  M.buf.close()
end

-- Views

-- Hex
M.hex = require("hex")
M.hex.setup(M.mem)

-- Disassembler
M.dis = require("dis")
M.dis.setup(M.mem, M.disasm)

-- Setup Vim integration
do
  local vim = require("vim")
  vim.close = M.close
  vim.setup()
end

return M

