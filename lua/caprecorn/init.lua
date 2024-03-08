local M = {}

-- Supported architectures
local arch = require("arch")
M.arch = arch.arch

setmetatable(M.arch, { __call = function(_, _arch)
  M._arch = _arch
end})

-- Memory and register access interfaces
-- Set up by the engine
M.mem = {}
M.reg = {}
M.emu = {}

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
      _unicorn.open(M._arch, M.reg)
      M._engine = _unicorn.engine
      M._disasm = _unicorn.disasm
      M.dis.setup(M)
    end

    local prev_close = M.close
    M.close = function()
      if prev_close ~=nil then
        prev_close()
      end
      _unicorn.close()
    end

    M.unstop = function()
      M._stopped = false
    end

    M.reg.pc = function(val)
      if M._engine == nil then
        error("Engine not initialized")
      end

      if val ~= nil then
        M._engine:reg_write(M.reg._pc, val)
      else
        return M._engine:reg_read(M.reg._pc)
      end
    end

    M.reg.sp = function(val)
      if M._engine == nil then
        error("Engine not initialized")
      end

      if val ~= nil then
        M._engine:reg_write(M.reg._sp, val)
      else
        return M._engine:reg_read(M.reg._sp)
      end
    end

    M.start = function(from, to, timeout, instructions)
      if M._stopped then
        return false, "Emulation stopped"
      end
      return M._engine:emu_start(from, to, timeout, instructions)
    end

    M.emu.stop = function ()
      M._stopped = true
    end

    M.emu.stopped = function ()
      return M.stopped()
    end

    M.emu.step = function()
      if not M.stopped() then
        print("Emulator is already running")
        return
      end
      local last_pc = M.reg.pc()
      local res, status = M._engine:emu_start(M.reg.pc(), -1, 0, 1)
      if not res then
        print(string.format("Error at PC=%016x", M.reg.pc()))
        error(status)
      else
        print(string.format("Step succeeded, previous PC=%016x, current PC=%016x", last_pc, M.reg.pc()))
      end
    end

    local idle = vim.loop.new_idle()

    M.emu.run = function()
      if not M.stopped() then
        print("Emulator is already running")
        return
      end
      print(string.format("Emulator started at PC=%016x", M.reg.pc()))
      M.unstop()

      idle:start(function()
        if M.stopped() then
          idle:stop()
          print(string.format("Emulator stopped at PC=%016x", M.reg.pc()))
          return
        end
        local res, status = M.start(M.reg.pc(), -1, 0, 101)
        if not res then
          idle:stop()
          M._stopped = true
          print(string.format("Error at PC=%016x", M.reg.pc()))
          error(status)
        end
      end)
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

    -- Registers
    M.reg.read = function(regs)
      local defs = M.reg.def

      local reg_ids = {}
      for _, p in ipairs(defs) do
        local reg_id = p[1]
        table.insert(reg_ids, reg_id)
      end

      local reg_values = { M._engine:reg_read_batch(unpack(reg_ids)) }

      return reg_values
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

-- Registers
M.reg = require("reg")
M.reg.setup(M.emu)

-- Disassembler
M.dis = require("dis")

-- Setup Vim integration
do
  local vim = require("vim")
  vim.close = M.close
  vim.setup()
end

-- Global key to stop emulator
M._stopped = true

M.stopped = function()
  return M._stopped
end

vim.keymap.set('n', '<F12>', function()
  M._stopped = true
end)




return M

