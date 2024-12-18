local M = {}

-- Debug log
local _log
_log = require("_log")

-- Supported architectures
local arch = require("arch")
M.arch = arch.arch

setmetatable(M.arch, { __call = function(_, _arch)
  M._arch = _arch
end})

M.mem = require("mem")

M.emu = {}

-- Breakpoints
M.brk = require("brk")

-- Symbol references etc
M.ref = require("ref")

-- Supported emulation engines
M.engine = {}
M.engine.UNICORN = "UNICORN"
M.engine.QILING = "QILING"

setmetatable(M.engine, { __call = function (_, engine)
  if M.engine[engine] ~= nil then
    M.__engine = engine
  else
    error(string.format("Unknown emulation engine=[%s]", engine))
  end

  if engine == M.engine.UNICORN then
    local _unicorn = require("uni")

    M.open = function()
      --TODO: error checks, tests (including invalid parameters)
      --TODO: separate Unicorn and Capstone

      M.emu.arch = M._arch
      _unicorn.open(M._arch, M.reg, M.emu, M.mem)
      M._engine = _unicorn.engine
      M._disasm = _unicorn.disasm
      M.flag = _unicorn.flag
      M.reg._flagid = _unicorn.flag -- Ugly, used in reg display
      M.dis.setup(M)
      M.elf.init()
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

    M.reg.flags = function(val)
      if M._engine == nil then
        error("Engine not initialized")
      end

      if val ~= nil then
        M._engine:reg_write(M.reg._flags, val)
      else
        return M._engine:reg_read(M.reg._flags)
      end
    end

    M.reg.flag = function(flag, val)
      if M._engine == nil then
        error("Engine not initialized")
      end

      if flag == nil then
        error("Flag not specified!")
      end

      local flags = M.reg.flags()
      local flag_mask = M.reg._flag[flag]
      if flag_mask == nil then
        -- Flag not supported by the architecture
        return nil
      end

      if val ~= nil then
        if val == false then
          flags = bit.band(flags, bit.bnot(flag_mask))
        elseif val == true then
          flags = bit.bor(flags, flag_mask)
        else
          error("Flag value must be either true or false!")
        end
        M.reg.flags(flags)
      else
        return bit.band(flags, flag_mask) ~= 0
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
        print("Emulator is already running (step)")
        return
      end

      local pc = M.reg.pc()
      M._engine:ctl_exits_disable()

      -- Call breakpoint callback, if it's defined for current address
      local breakpoint = M.brk.brk[pc]
      if breakpoint ~= nil then
        if breakpoint.callback then
          _ = breakpoint.callback()
        end
      end

      local res, status = M._engine:emu_start(M.reg.pc(), -1, 0, 1)

      M._engine:ctl_exits_enable()

      if not res then
        print("[", status, "]", string.format("Error at PC=%016x", M.reg.pc()))
      else
        print(string.format("Step succeeded, previous PC=%016x, current PC=%016x", pc, M.reg.pc()))
      end
      if M.emu.stop_pc ~= nil then
        M.reg.pc(M.emu.stop_pc)
        M.emu.stop_pc = nil
      end
    end

    local idle = vim.loop.new_idle()

    M.emu.run = function(arg)
      if not M.stopped() then
        print("Emulator is already running (run)")
        return
      end
      print(string.format("Emulator started at PC=%016x", M.reg.pc()))
      M.unstop()

      arg = arg or {}
      local steps = arg.steps or 100
      local stop_pc = arg.stop_pc

      idle:start(function()
        if M.stopped() then
          idle:stop()
          print(string.format("Emulator stopped at PC=%016x", M.reg.pc()))
          if M.emu.stop_pc ~= nil then
            M.reg.pc(M.emu.stop_pc)
            M.emu.stop_pc = nil
          end
          return
        end

        local start_pc = M.reg.pc()

        local steps_passed = 0
        steps = steps or 100
        while steps_passed < steps do

          local pc = M.reg.pc()
          local breakpoint

          if not stop_pc then
            breakpoint = M.brk.brk[pc]
          end

          if stop_pc or breakpoint then
            local stop = pc == stop_pc or (breakpoint and pc ~= start_pc)
            if breakpoint and breakpoint.callback then
              stop = breakpoint.callback()
            end
            if stop then
              idle:stop()
              M._stopped = true
              print(string.format("Emulator stopped at breakpoint PC=%016x", pc))
              break
            end
          end

          local res, status = M.start(pc, -1, 0, 1)
          if not res then
            idle:stop()
            M._stopped = true
            print(string.format("Error at PC=%016x, status=[%s]", M.reg.pc(), status))
          end

          steps_passed = steps_passed + 1
        end
      end)
    end

    M.emu.set_breakpoints = function(address_list)
      M._engine:ctl_set_exits(address_list)
    end

    M.stop = function()
      M._engine:emu_stop()
    end

    -- Registers
    -- Debug function that reads registers one-by-one
    M.reg.read_ = function(reg_ids)
      local reg_values = {}

      for i = 1, #reg_ids do
        local reg_id = reg_ids[i]
        local reg_name = M.reg.name(reg_id)
        local reg_value = M._engine:reg_read(reg_id)
        table.insert(reg_values, reg_value)
      end

      return reg_values
    end

    -- Batch read
    M.reg.read = function(reg_ids)
      --TODO: return based on the parameter (dynamic, for instance, show only registers used by a certain function)
      --Support register groups (general purpose, segment, XMM/YMM/ZMM, system CRx/DRx/...)
      --Return status and value
      --Return 64-bit values as two 32-bit  

      local reg_values

      if type(reg_ids) == "table" then
        reg_values = { M._engine:reg_read_batch(unpack(reg_ids)) }
      else
        reg_values = M._engine:reg_read(reg_ids)
      end

      return reg_values
    end

    M.reg.write_buf = function(reg_id, buf)
      local status, err = M._engine:reg_write_buf(reg_id, buf)

      if not status then
        error(string.format("Register [%s] write failed error=[%s]", M.reg.name(reg_id), tostring(err)))
      end
    end

    M.reg.write = function(reg_id, val)
      local status, err = M._engine:reg_write(reg_id, val)

      if not status then
        error(string.format("Register [%s] value %016x write failed error=[%s]", M.reg.name(reg_id), val, tostring(err)))
      end
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
M.win = require("win")

M.close = function()
  M.win.close()
  M.buf.close()
end

-- Vim integration
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

-- Hex
M.hex = require("hex")
M.hex.setup(M.mem)

-- Registers
M.reg = require("reg")
M.reg.setup(M.emu)

-- Buffers
M.buf = require("buf")
M.buf.reg = M.reg
M.buf.ref = M.ref

-- Disassembler
M.dis = require("dis")

-- ELF file loader
M.elf = require("elf")
M.elf.setup(M.emu, M.mem, M.reg)

return M

