-- Disassembler and debugger

local M = {}

-- Needed for register constants
-- Yes, abstraction leaks here
local capstone = require("capstone")

M.mem = nil
M.reg = nil
M.disasm = nil
M.emu = nil

-- Cross-references, functions, etc.
-- [[
-- {
--  [addr] = {
--    refs_from = {
--      [
--        addr = 
--        type = CALL | JUMP
--      ]
--    }
--    ref_to = {
--      addr =
--      type =
--    }
--    names = { 
--    }
--  }
-- }
-- ]]

local REF_CALL = 1
local REF_JUMP = 2

M.refs = {}

-- References: symbols etc
local ref = require("ref")
M.sym = ref.sym
M.datatype = ref.datatype

-- Breakpoints
local brk = require("brk")
M.brk = brk.brk

-- To avoid disassembling gigabytes or more of code. User can change this, if needed
M.maxsize = 64 * 1024

local function create_highlight()
  vim.cmd([[
  hi default link CrcDisNormal Normal
  hi default CrcDisComment guifg=#333333
  hi default CrcDisFunc guifg=#ff0000
  hi default CrcDisDef guifg=#ff0000 gui=bold
  hi default CrcDisLocal guifg=#05a5af
  hi default CrcDisCall guifg=#aa0000
  hi default CrcDisJump guifg=#008585
  hi default CrcDisTarget guifg=#cccc00
  hi default CrcDisSymbol gui=bold guifg=#00ff00
  hi default CrcDisPc gui=bold guifg=#00ff00
  hi default CrcDisBrk gui=bold guifg=#ffaa00 
  hi default CrcDisForcedRedisassembly guibg=#ff5500 guifg=#000000
  hi default CrcDisForcedRedisassemblyText guifg=#ff5500
  ]])
end

M.setup = function(C)
  M.mem = C.mem
  M.reg = C.reg
  M.disasm = C.disasm
  M.emu = C.emu

  create_highlight()
end

local function insn_refs(insn, refs)
  local groups = insn.detail.groups
  local groups_size = #groups

  local iscall = false
  local isjump = false

  for i = 0, groups_size - 1 do
    local g = groups[i]
    if g == 7 then isjump = true
    elseif g == 2 then iscall = true end
  end

  local id = insn.id
  if id == 349 or id == 350 then -- loopz, loopnz
    isjump = true
  end

  if iscall or isjump then
    if insn.detail.x86 ~= nil then
      if insn.detail.x86.op_count == 1 then
        if insn.detail.x86.operands[1].type == capstone.X86_OP_IMM then
          local dest = insn.detail.x86.operands[1].imm

          local ref = refs[dest]
          if ref == nil then
            ref = { refs_from = {} }
            refs[dest] = ref
          end
          if ref.refs_from == nil then
            ref.refs_from = {}
          end
          local ref_type
          if iscall then ref_type = REF_CALL else ref_type = REF_JUMP end
          table.insert(ref.refs_from, { addr = insn.address, type = ref_type })

          ref = refs[insn.address]
          if ref == nil then
            ref = { ref_to = {} }
            refs[insn.address] = ref
          end
          if ref.ref_to == nil then
            ref.ref_to = {}
          end
          ref.ref_to.addr = dest
          ref.ref_to.type = ref_type

          return string.format("%016x ref_type=%d", dest, ref_type)
        else
          return string.format("insn.detail.x86.operands[1].type == %s", insn.detail.x86.operands[1].type)
        end
      else
        return string.format("insn.detail.x86.op_count == %s", insn.detail.x86.op_count)
      end
    else
      return "insn.detail.x86 == nil"
    end
  else
    return "?"
  end

  return ""
end

local function insn_ref_addr(insn, addr)
  local res = nil

  local groups = insn.detail.groups
  local groups_size = #groups

  local iscall = false
  local isjump = false

  for i = 0, groups_size - 1 do
    local g = groups[i]
    if g == 7 then isjump = true
    elseif g == 2 then iscall = true end
  end

  local id = insn.id
  if id == 349 or id == 350 then -- loopz, loopnz
    isjump = true
  end

  if insn.detail.x86 ~= nil then
    if insn.detail.x86.op_count > 0 then
      local op = insn.detail.x86.operands[1]
      if op.type == capstone.X86_OP_IMM then
        local base = op.imm
        if M.sym[base] ~= nil then
          res = base
        end
      else
        op = insn.detail.x86.operands[2]
        if op then
          if op.type == capstone.X86_OP_IMM then
            local base = op.imm
            if M.sym[base] ~= nil then
              res = base
            end
          end
        end
      end
    end
  end

  return res
end

local function insn_access_addr(insn, addr)
  local res = nil

  if insn.detail.x86 ~= nil then
    for i = 1, insn.detail.x86.op_count do
      local op = insn.detail.x86.operands[i]
      local op_type = op.type
      if op_type == capstone.X86_OP_MEM then
        local base = op.mem.base
        if base == capstone.X86_REG_RIP or base == capstone.X86_REG_EIP then
          local disp = op.mem.disp
          -- Assume displacement is 32 bits maximum
          if disp > 0x7fffffff then
            disp = -disp
          end
          res = addr + insn.size + disp
          break
        end
      end
    end
  end

  return res
end

local function dis(start, bytes, opts)

  local code
  if bytes ~= nil then
    if type(bytes) == "string" then
      code = bytes
    else
      code = ""
      for _, n in pairs(bytes) do
         code = code .. string.char(n)
      end
    end
  else
    code = ""
  end

  local ensure_addr_list = opts.ensure_contains_addrs

  -- Disassemble

  local it = M.disasm.createiterator(start, code)
  local code_offset = 0

  local highlight = {}
  local lines = {}
  local tags = {}

  M.refs = {}
  --TODO: xrefs key should be [to_ref, from_ref] 
  -- Or maybe [to_ref] = { [from_ref] = { type = ..., analysis_type = 'STATIC', ... } }

  local forced_redisassembly_addresses = {}
  local custom_highlights = {}

  local last_addr = nil
  local addr
  while true do

    if not M.disasm.disasmiter(it) then
      break
    end
    addr = it.insn.address

    local datatype = M.datatype[addr]
    if datatype ~= nil and datatype.data then
      local size = datatype.size or 1
      local count = datatype.count or 1
      local nbytes = count * size

      local line = "data " .. tostring(size) .. " * " .. tostring(count)
      table.insert(lines, line)

      code = string.sub(code, code_offset + nbytes + 1)
      code_offset = 0
      M.disasm.freeiterator(it)
      it = M.disasm.createiterator(addr + nbytes, code)

      local hl = { addr = addr }
      table.insert(highlight, hl)

      local tag = {
        addr = addr,
        access_addr = nil,
        ref_addr = nil,
        insn_size = size,
      }
      table.insert(tags, tag)

      goto continue
    end

    local custom_disasm = false
    local custom_size, custom_mnemonic, custom_op_str, custom_disasm_highlight
    if opts.disasm_callback then
      custom_disasm, custom_size, custom_mnemonic, custom_op_str, custom_disasm_highlight
        = opts.disasm_callback(addr, code, code_offset)
      custom_highlights[addr] = custom_disasm_highlight
    end

    local done = false
    if ensure_addr_list ~= nil then
      if last_addr ~= nil then
        for _, ensure_addr in pairs(ensure_addr_list) do
          if ensure_addr > last_addr and ensure_addr < addr then
            -- Address in the middle of current instruction, re-disassemble
            forced_redisassembly_addresses[last_addr] = true
            code_offset = code_offset - (addr - ensure_addr)
            code = string.sub(code, code_offset + 1)
            M.disasm.freeiterator(it)
            it = M.disasm.createiterator(ensure_addr, code)
            if not M.disasm.disasmiter(it) then
              done = true
              break
            end
            code_offset = 0
            addr = it.insn.address
            last_addr = nil
            break
          end
        end
      end
      last_addr = addr
    end
    if done then
      break
    end

    local size

    if custom_disasm then
      size = custom_size
    else
      size = it.insn.size
    end

    local bytes_str = ""
    for i = 0, size - 1 do
      local byte = string.byte(string.sub(code, code_offset + i + 1, code_offset + i + 1))
      if byte ~= nil then
        bytes_str = bytes_str .. string.format("%02x", byte)
      end
    end

    code_offset = code_offset + size

    local regs_read_count = it.insn.detail.regs_read_count
    local regs_read = it.insn.detail.regs_read
    local regs_write_count = it.insn.detail.regs_write_count
    local regs_write = it.insn.detail.regs_write

    local regs_read_str = ""
    for i = 0, regs_read_count - 1 do
      local disasm_reg_id = regs_read[i] or 0
      local reg_id = M.reg.disasm_reg_id(disasm_reg_id)
      local reg_name
      if reg_id == nil then
        -- print("Disasm reg nil", disasm_reg_id, "at addr", string.format("%016x", addr))
        reg_name = "???"
      else
        reg_name = M.reg.name(reg_id)
      end
      regs_read_str = regs_read_str .. reg_name .. " "
    end

    local regs_write_str = ""
    for i = 0, regs_write_count - 1 do
      local disasm_reg_id = regs_write[i] or 0
      local reg_id = M.reg.disasm_reg_id(disasm_reg_id)
      local reg_name = M.reg.name(reg_id)
      regs_write_str = regs_write_str .. reg_name .. " "
    end

    insn_refs(it.insn, M.refs)
    local access_addr = insn_access_addr(it.insn, addr)
    local access_addr_str = ""
    if access_addr ~= nil then
      local sym = M.sym[access_addr]
      if sym == nil then
        access_addr_str = string.format(" (%016x)", access_addr)
      else
        access_addr_str = string.format(" (%s: %016x)", sym, access_addr)
      end
    end

    local ref_addr = insn_ref_addr(it.insn, addr)
    if ref_addr ~= nil then
      local sym = M.sym[ref_addr]
      if sym ~= nil then
        access_addr_str = string.format(" (%s)", sym, ref_addr)
      end
    end

    local mnemonic
    local op_str

    if custom_disasm then
      mnemonic = custom_mnemonic
      op_str = custom_op_str
    else
      mnemonic = it.insn.mnemonic
      op_str = it.insn.op_str .. access_addr_str
    end

    local line = string.format("%016x   %-24s %-10s %-42s", -- [%s<= %s]",
      addr, bytes_str, mnemonic, op_str) --, regs_write_str, regs_read_str)

    table.insert(lines, line)

    local hl = { addr = it.insn.address }
    table.insert(highlight, hl)

    local tag = {
      addr = addr,
      access_addr = access_addr,
      ref_addr = ref_addr,
      insn_size = size,
    }
    table.insert(tags, tag)

    if custom_disasm then
      code = string.sub(code, code_offset + 1)
      code_offset = 0
      M.disasm.freeiterator(it)
      it = M.disasm.createiterator(addr + custom_size, code)
    end

    ::continue::
  end

  --TODO: Fix crash
  M.disasm.freeiterator(it)

  -- Highlight
  local pc = opts.pc

  for i = 1, #highlight do
    local hl = highlight[i]
    local addr = hl.addr

    if M.brk[addr] ~= nil then
      hl.highlights = hl.highlights or {}
      local hl_addr = {
        line = i - 1,
        start_col = 0,
        --hl_group = 'CrcDisBrk',
        end_col = 0,
        priority = 90,
        virt_text_win_col = 18,
        virt_text = {{'', 'CrcDisBrk'}},
      }
      table.insert(hl.highlights, 1, hl_addr)
    end

    if pc ~= nil and addr == pc then
      hl.highlights = hl.highlights or {}
      local hl_addr = {
        line = i - 1,
        start_col = 0,
        --hl_group = 'CrcDisPc',
        end_col = 0,
        priority = 90,
        virt_text_win_col = 17,
        virt_text = {{'󰐊', 'CrcDisPc'}},
      }
      table.insert(hl.highlights, 1, hl_addr)

      opts.pc_line = i
    end

    if forced_redisassembly_addresses[addr] then
      hl.highlights = hl.highlights or {}
      local hl_addr = {
        line = i - 1,
        start_col = 0,
        hl_group = 'CrcDisForcedRedisassembly',
        end_col = 16,
        priority = 80,
        virt_text = {{'Ref inside instruction', 'CrcDisForcedRedisassemblyText'}},
      }
      table.insert(hl.highlights, 1, hl_addr)
    end

    local sym = M.sym[addr]

    if sym ~= nil then
      hl.highlights = hl.highlights or {}

      local hl_name = {
        line = i - 1,
        start_col = 0,
        hl_group = 'CrcDisFunc',
        virt_lines = {{{sym .. ":", 'CrcDisSymbol'}}},
        virt_lines_above = true,
        priority = 99,
      }
      table.insert(hl.highlights, 1, hl_name)
    end

    local custom_highlight = custom_highlights[addr]
    if custom_highlight ~= nil then
      hl.highlights = hl.highlights or {}

      if type(custom_highlight) == "table" then
        for _, custom_highlight1 in ipairs(custom_highlight) do
          custom_highlight1.line = i - 1
          table.insert(hl.highlights, 1, custom_highlight1)
        end
      else
        custom_highlight.line = i - 1
        table.insert(hl.highlights, 1, custom_highlight)
      end
    end

    local ref = M.refs[addr]
    if ref ~= nil then
      if ref.refs_from ~= nil then
        hl.highlights = hl.highlights or {}

        local iscall = false
        local isjump = false

        for _, v in ipairs(ref.refs_from) do
          local xrefs_text = {}
          if v.type == REF_CALL then
            iscall = true
            table.insert(xrefs_text, { "; Call from ", 'CrcDisComment' })
            table.insert(xrefs_text, { string.format("%016x [%d]", v.addr, #hl.highlights), 'CrcDisCall' })
          elseif v.type == REF_JUMP then
            isjump = true
            table.insert(xrefs_text, { "; Jump from ", 'CrcDisComment' })
            table.insert(xrefs_text, { string.format("%016x [%d]", v.addr, #hl.highlights), 'CrcDisJump' })
          end
          local hl_xrefs = {
            line = i - 1,
            start_col = 0,
            virt_lines_above = true,
            virt_lines = { xrefs_text },
            priority = 20,
          }
          table.insert(hl.highlights, 1, hl_xrefs)
        end

        if iscall then
          if M.sym[addr] == nil then
            local label = string.format('func_%016x: [%d]', addr, #hl.highlights)

            local hl_name = {
              line = i - 1,
              start_col = 0,
              hl_group = 'CrcDisFunc',
              virt_lines = {{{label, 'CrcDisTarget'}}},
              virt_lines_above = true,
              priority = 99,
            }
            table.insert(hl.highlights, 1, hl_name)
          end
        end

        local hl_group
        if iscall then
          hl_group = 'CrcDisFunc'
        else
          hl_group = 'CrcDisLocal'
        end

        local hl_addr = {
          line = i - 1,
          start_col = 0,
          hl_group = hl_group,
          end_col = 16,
        }
        table.insert(hl.highlights, 1, hl_addr)
      end
      if ref.ref_to ~= nil then
        local isjump = false
        local iscall = false
        if hl.highlights == nil then
          hl.highlights = {}
        end
        if ref.ref_to.type == REF_CALL then iscall = true
        elseif ref.ref_to.type == REF_JUMP then isjump = true
        end
        local hl_group
        if iscall then
          hl_group = 'CrcDisCall'
        else
          hl_group = 'CrcDisJump'
        end
        local hl_addr = {
          line = i - 1,
          start_col = 16 + 24 + 4,
          hl_group = hl_group,
          end_col = 16 + 24 + 4 + 10,
        }
        table.insert(hl.highlights, 1, hl_addr)

        if iscall then
          hl_group = 'CrcDisTarget'
        else
          hl_group = 'CrcDisJump'
        end
        local hl_addr2 = {
          line = i - 1,
          start_col = 55,
          hl_group = hl_group,
          end_col = 55 + 2 + 16,
        }
        table.insert(hl.highlights, 1, hl_addr2)
      end
    end
  end

  return lines, highlight, tags
end

local function setup_keymaps(buffer)
  vim.keymap.set('n', 'l',
    function()
      local row = vim.api.nvim_win_get_cursor(0)[1]
      local tag = (buffer.hex.tags or {})[row]
      if tag == nil then
        return
      end
 
      local addr = tag.addr

      vim.fn.inputsave()
      local label = vim.fn.input("Input label:")
      vim.fn.inputrestore()
      if label == "" then
        return
      end

      M.sym[addr] = label

      buffer:jump(addr)

    end,
    { buffer = buffer.handle(), desc = " Label current address"}
  )

  vim.keymap.set('n', 'ga',
    function()
      local addr

      vim.fn.inputsave()
      local addr_str = vim.fn.input("Input address or +/-offset:")
      vim.fn.inputrestore()
      if addr_str == "" then
        return
      end
      addr_str = addr_str:gsub("%s+", "")
      addr = tonumber(addr_str)
      if addr == nil or #addr_str == 0 then
        error("Invalid address!")
      end
      local sign = string.sub(addr_str, 1, 1)
      if sign == "+" then
        addr = buffer.hex.from + buffer.hex.size + addr
      elseif sign == "-" then
        addr = buffer.hex.from + addr
      end

      buffer:jump(addr)

    end,
    { buffer = buffer.handle(), desc = " Go to address"}
  )

  vim.keymap.set('n', 'gp',
    function()
      local addr = M.reg.pc()

      buffer:jump(addr)
    end,
    { buffer = buffer.handle(), desc = " Go to PC"}
  )

  vim.keymap.set('n', 'gr',
    function()
      local row = vim.api.nvim_win_get_cursor(0)[1]
      local tag = (buffer.hex.tags or {})[row]
      if tag ~= nil then
        local addr = tag.access_addr or tag.ref_addr
        if addr ~= nil then
          if buffer.hex.jump_history == nil then
            buffer.hex.jump_history = {}
          end
          table.insert(buffer.hex.jump_history, tag.addr)

          buffer:jump(addr)
        end
      end
    end,
    { buffer = buffer.handle(), desc = " Go to referenced address"}
  )

  vim.keymap.set('n', 'gb',
    function()
      if buffer.hex.jump_history == nil or #buffer.hex.jump_history == 0 then
        return
      end

      local addr = buffer.hex.jump_history[#buffer.hex.jump_history]
      table.remove(buffer.hex.jump_history, #buffer.hex.jump_history)

      buffer:jump(addr)
    end,
    { buffer = buffer.handle(), desc = " Go back"}
  )

  vim.keymap.set('n', 'b',
    function()
      local row = vim.api.nvim_win_get_cursor(0)[1]
      local tag = (buffer.hex.tags or {})[row]
      if tag ~= nil then
        local addr = tag.addr
        if addr ~= nil then
          if M.brk[addr] ~= nil then
            M.brk[addr] = nil
          else
            M.brk[addr] = { addr = addr, }
          end

          buffer:jump(addr)
        end
      end
    end,
    { buffer = buffer.handle(), desc = " Set/delete breakpoint"}
  )

  vim.keymap.set('n', 'bd',
    function()
      M.emu.set_breakpoints({})
    end,
    { buffer = buffer.handle(), desc = " Delete breakpoints"}
  )

  local show_running_status = function()
    local runstatus
    if M.emu.stopped() then
      runstatus = "STOPPED"
    else
      runstatus = "RUNNING"
    end
    vim.api.nvim_win_set_option(0, "winbar", runstatus .. string.format(" PC=%016x", M.reg.pc()))
    vim.cmd("redrawstatus!")
    --print(string.format("Emulator " .. string.lower(runstatus) .. " at PC=%016x", M.reg.pc()))
  end

  vim.api.nvim_create_autocmd({"BufEnter", "CursorMoved", "User", "CursorHold"}, {
    buffer = buffer.handle(),
    callback = show_running_status,
  })

  local step = function()
    M.emu.step()

    show_running_status()

    buffer:jump(M.reg.pc())

    if buffer.hex.opts.pc_line ~= nil then
      vim.cmd(":" .. tostring(buffer.hex.opts.pc_line))
    end
    local curr_line = vim.fn.line('.')
    local first_line = vim.fn.line('w0')
    local last_line = vim.fn.line('w$')
    if last_line - first_line > 0 then
      local too_low_line = last_line - math.floor(0.15 * (last_line - first_line))
      if curr_line >= too_low_line then
        vim.cmd([[execute "normal zz"]])
      end
    end


    if buffer.on_change ~= nil then
      buffer.on_change()
    end
  end

  vim.keymap.set('n', 's', step, { buffer = buffer.handle(), desc = "Step"})
  vim.keymap.set('n', '<F7>', step, { buffer = buffer.handle(), desc = "Step"})

  vim.keymap.set('n', 'D', function ()
    buffer:jump(buffer.hex.from)
  end, { buffer = buffer.handle(), desc = "Step"})

  local timer = vim.loop.new_timer()

  local run = function()
    timer:start(500, 500, vim.schedule_wrap(function()
      show_running_status()
      if buffer.on_change ~= nil then
        buffer.on_change()
      end
      if M.emu.stopped() then
        timer:stop()
        
        buffer:jump(M.reg.pc())
      end
    end))

    M.emu.run()

    show_running_status()
  end

  vim.keymap.set('n', 'r', run, { buffer = buffer.handle(), desc = " Run"})
  vim.keymap.set('n', '<F9>', run, { buffer = buffer.handle(), desc = " Run"})

  vim.keymap.set('n', 'S', function()
    M.emu.stop()
  end, { buffer = buffer.handle(), desc = " Stop"})

  vim.keymap.set('n', 'vb',
    function()
      if buffer.hex.opts.show_bytes then
        buffer.hex.opts.show_bytes = false
      else
        buffer.hex.opts.show_bytes = true
      end

      --TODO: Move to a separate function, like buffer:dump(), but think first 
      M.dis(buffer, buffer.hex.from, buffer.hex.size, buffer.hex.opts)

    end,
    { buffer = buffer.handle(), desc = " Show/hide bytes"}
  )

  buffer.go_to_pc = function()
    local addr = M.reg.pc()

    buffer:jump(addr)

    show_running_status()
  end
end

local function jump(buffer, addr)
  local from
  local size

  from = buffer.hex.from
  size = buffer.hex.size

  local opts = buffer.hex.opts or {}
  opts.pc = M.reg.pc()
  opts.ensure_contains_addrs = { addr, M.reg.pc() }

  if addr < buffer.hex.from or addr > buffer.hex.from + buffer.hex.size then
    if addr < buffer.hex.from then
      from = addr
      size = buffer.hex.size + (buffer.hex.from - addr)
    else
      from = buffer.hex.from
      size = addr - buffer.hex.from + 1
      if size > M.maxsize or (opts.maxsize ~= nil and size > opts.maxsize) then
        from = addr
        size = math.min(M.maxsize, opts.maxsize or M.maxsize)
      end
    end
  end

  M.dis(buffer, from, size, opts)

  local tags = buffer.hex.tags or {}
  for row, tag in ipairs(tags) do
    if tag.addr == addr then
      vim.cmd(":" .. tostring(row))
      break
    end
  end

  --TODO: Move cursor in GUI to the specified address
end

M.dis = function(buffer, from, size_or_bytes, opts)
  local bytes
  local size
  local fixed = false

  --TODO: Move to a separate util module that would do validations
  if buffer == nil then
    error("Buffer is nil for disassembly")
  end

  if type(size_or_bytes) == "string" then
    bytes = size_or_bytes
    size = #bytes
    fixed = true
  else
    if type(size_or_bytes) == "number" then
      if M.mem == nil then
        error("Memory is not initialized yet")
      end
      size = size_or_bytes
      if size < 0 then
        error(string.format("Size of memory to disassemble cannot be negative, size=[%d]", size))
      end

      if size > M.maxsize then
        size = M.maxsize
        if opts.maxsize and opts.maxsize < size then
          size = opts.maxsize
        end
        print(string.format("Disassembly size truncated to %d bytes", M.maxsize))
      end
      bytes = M.mem.read(from, size)

    else
      error(string.format("Disassembler expects either a fixed byte string, or an address and size, received [%s] type [%s]",
        tostring(size_or_bytes), tostring(type(size_or_bytes))))
    end
  end

  opts = opts or {}

  local lines, highlight, tags = dis(from, bytes, opts)

  buffer.update(lines, highlight)

  if buffer.hex == nil then
    buffer.hex = {}
  end
  buffer.hex.tags = tags
  buffer.hex.opts = opts
  buffer.hex.opts.fixed = fixed
  if buffer.hex.opts.show_bytes == nil then
    buffer.hex.opts.show_bytes = true
  end
  buffer.hex.from = from
  buffer.hex.size = size
  if not fixed then
    buffer.hex.mem = M.mem
    buffer.jump = jump
  end

  setup_keymaps(buffer)

end

return M



