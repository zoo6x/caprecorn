-- Disassembler and debugger

local M = {}

M.mem = nil
M.disasm = nil

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

-- To avoid disassembling gigabytes or more of code. User can change this, if needed
M.maxsize = 64 * 1024

local function create_highlight()
  vim.cmd([[
  hi default link CrcDisNormal Normal
  hi default CrcDisComment guifg=#333333
  hi default CrcDisFunc guifg=#ff0000
  hi default CrcDisLocal guifg=#05a5af
  hi default CrcDisCall guifg=#aa0000
  hi default CrcDisJump guifg=#008585
  hi default CrcDisTarget guifg=#cccc00
  ]])
end

M.setup = function(mem, disasm)
  M.mem = mem
  M.disasm = disasm

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
        if insn.detail.x86.operands[1].type == 2 then -- IMM
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

  -- Disassemble

  local it = M.disasm.createiterator(start, code)

  local highlight = {}
  local lines = {}

  while M.disasm.disasmiter(it) do
    local size = it.insn.size
    local bytes_str = ""
    for i = 0, size - 1 do
      local byte = it.insn.bytes[i]
      bytes_str = bytes_str .. string.format("%02x", byte)
    end

    local ref_str = insn_refs(it.insn, M.refs)

    local line = string.format("%016x   %-24s %-10s %s",
      it.insn.address, bytes_str, it.insn.mnemonic, it.insn.op_str)

    table.insert(lines, line)

    local hl = { addr = it.insn.address }
    table.insert(highlight, hl)

  end

  M.disasm.freeiterator(it)

  -- Highlight

  for i = 1, #highlight do
    local hl = highlight[i]
    local addr = hl.addr

    local ref = M.refs[addr]
    if ref ~= nil then
      if ref.refs_from ~= nil then
        if hl.highlights == nil then
          hl.highlights = {}
        end

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
          local hl_name = {
            line = i - 1,
            start_col = 0,
            hl_group = 'CrcDisFunc',
            virt_lines = {{{string.format('func_%016x: [%d]', addr, #hl.highlights), 'CrcDisTarget'}}},
            virt_lines_above = true,
            priority = 99,
          }
          table.insert(hl.highlights, 1, hl_name)
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
        local hl_addr2 = {
          line = i - 1,
          start_col = 55,
          hl_group = 'CrcDisTarget',
          end_col = 55 + 2 + 16,
        }
        table.insert(hl.highlights, 1, hl_addr2)
      end
    end
  end

  return lines, highlight
end

local function setup_keymaps(buffer)
  if not buffer.hex.opts.fixed then
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
      { buffer = buffer.handle(), desc = "Go to address"}
    )

    vim.keymap.set('n', 'E',
      function()
        print("Edit mode (TBD)")
      end
    )
  end

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
    { buffer = buffer.handle(), desc = "Show/hide bytes"}
  )

end

local function jump(buffer, addr)
  if addr < buffer.hex.from or addr > buffer.hex.from + buffer.hex.size then
    local from
    local size
    if addr < buffer.hex.from then
      from = addr
      size = buffer.hex.size + (buffer.hex.from - addr)
    else
      from = buffer.hex.from
      size = addr - buffer.hex.from + 1
      if size > M.maxsize then
        from = addr
        size = 4096
      end
    end

    M.dis(buffer, from, size)
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
        print(string.format("Disassembly size truncated to %d bytes", M.maxsize))
      end
      bytes = M.mem.read(from, size)

    else
      error(string.format("Disassembler expects either a fixed byte string, or an address and size"))
    end
  end

  local lines, highlight = dis(from, bytes, opts)

  buffer.update(lines, highlight)

  if buffer.hex == nil then
    buffer.hex = {}
  end
  buffer.hex.opts = opts or {}
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
  --buffer.dump = dump

  setup_keymaps(buffer)
end


return M



