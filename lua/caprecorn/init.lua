local M = {}

-- Supported architectures
local arch = require("arch")
M.arch = arch.arch

setmetatable(M.arch, { __call = function(_, _arch)
  M._arch = _arch
end})

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

    M.close = _unicorn.close

    M.start = function(from, to)
      M._engine:emu_start(from, to)
    end

    M.stop = function()
      M._engine:emu_stop()
    end

    M.mem = {}

    M.mem.map = function(from, size)
      M._engine:mem_map(from, size)
    end

    M.mem.write = function(from, bytes)
      M._engine:mem_write(from, bytes)
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

-- Setup Vim integration

require("vim").setup()

return M

