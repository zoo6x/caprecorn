local qiling = {}

qiling.name = "Caprecorn"

function qiling.unicorn()
  if qiling.uc == nil then
    qiling.uc = require("unicorn")
  end
  return qiling.uc
end

function qiling.capstone()
  if qiling.cs == nil then
    qiling.cs = require("capstone")
  end
  return qiling.cs
end

function qiling.open(name, lines, append)
  local tab_count = vim.api.nvim_call_function('tabpagenr', {'$'})

  if tab_count < 2 then
  --  vim.api.nvim_command('tabnew')
  end

  local buf_handle = vim.api.nvim_call_function('bufnr', {name})
  if buf_handle == -1 then
    buf_handle = vim.api.nvim_create_buf(true, true)
    local buf_name = "caprecorn://" .. name
    vim.api.nvim_buf_set_name(buf_handle, buf_name)

    vim.cmd("new " .. buf_name)
  end
  if append then
    local line_count = vim.api.nvim_buf_line_count(buf_handle)
    vim.api.nvim_buf_set_lines(buf_handle, line_count, line_count, false, lines)
  else
    vim.api.nvim_buf_set_lines(buf_handle, 0, -1, false, lines)
  end

  return buf_handle
end

function qiling.hex(name, start, bytes)
  local start0 = start - start % 16
  local finish = start + #bytes
  local lines = {}
  local line = ""
  local chars = ""
  local i = 1

  local header = "                   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F   0123456789ABCDEF"
  table.insert(lines, header)

  while start0 < finish do
    if start0 % 16 == 0 then
      if line ~= "" then
        line = line .. "  " .. chars
        table.insert(lines, line)
        line = ""
        chars = ""
      end
      line = line .. string.format("%016x  ", start0)
    end
    if start0 < start then
      line = line .. "   "
      chars = chars .. " "
    else
      local c
      if type(bytes) == 'string' then
        c = bytes:byte(i)
      else
        c = bytes[i]
      end
      line = line .. string.format("%02x ", c)
      if c < 32 or c > 127 then c = 46 end
      chars = chars .. string.char(c)
      i = i + 1
    end
    start0 = start0 + 1
  end
  local trail = 16 - finish % 16
  if trail > 0 and trail < 16 then
    line = line .. string.rep("   ", trail)
  end
  table.insert(lines, line .. "  " .. chars)

  local buf_handle = qiling.open(name, lines)

  vim.keymap.set('n', 'ga',
    function()
      vim.fn.inputsave()
      local addr_str = vim.fn.input("Input address:")
      vim.fn.inputrestore()
      local addr = tonumber(addr_str)
      if addr == nil then
        print("Invalid address!")
        return
      end
      local uc = qiling.unicorn()
      --TODO: need an open engine here to read memory!
    end,
    { buffer = buf_handle, desc = "Go to address"}
  )
end

function qiling.dis(name, start, bytes)

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
    code = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6"
  end

  local capstone = qiling.capstone()
  local err, handle = capstone.open(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

  if err ~= capstone.CS_ERR_OK then
    print("Failed to load Capstone")
    return
  end

  capstone.option(handle, capstone.CS_OPT_DETAIL, capstone.CS_OPT_ON)
  capstone.option(handle, capstone.CS_OPT_SKIPDATA, capstone.CS_OPT_ON)
  local it = capstone.createiterator(handle, code, #code, start)

  local lines = {}

  while capstone.disasmiter(handle, it) do
    local size = it.insn.size
    local bytes_str = ""
    for i = 0, size - 1 do
      local byte = it.insn.bytes[i]
      bytes_str = bytes_str .. string.format("%02x", byte)
    end

    local line = string.format("%08x   %-16s  %-16s %s", it.insn.address, bytes_str, it.insn.mnemonic, it.insn.op_str)

    table.insert(lines, line)
  end

  -- capstone.freeiterator(it)

  local buf_handle = qiling.open(name, lines)

  vim.api.nvim_buf_set_option(buf_handle, 'filetype', 'caprecorn_disasm')

  -- Number entered before is in vim.v.count
  vim.keymap.set('n', '<F7>', function() print("Debug!") end, { buffer = buf_handle, desc = "Debug Step"})
  vim.keymap.set('n', '<C-F>', function() print("Forward!") end, { buffer = buf_handle, desc = "Disasm Forward"})
  vim.keymap.set('n', '<C-B>', function() print("Back!") end, { buffer = buf_handle, desc = "Disasm Back"})
end

vim.cmd([[command! Test lua Ql.dis('QQQ', 0x4000, {0x55, 0x88, 0x41, 0x42}) ]])

return qiling

