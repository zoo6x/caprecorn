-- Hexadecimal dump viewer and editor

local M = {}

M.mem = nil

-- To avoid dumping gigabytes or more of memory. User can change this, if needed
M.maxsize = 1024 * 1024

M.setup = function(mem)
  M.mem = mem
end

M.hex = function (start, bytes, opts)
  local start0 = start - start % 16
  local finish = start + #bytes
  local lines = {}
  local line = ""
  local show_chars = true
  local chars = ""
  local i = 1

  if opts then
    if opts.show_chars ~= nil then
      show_chars = opts.show_chars
    end
  end

  local header
  --TODO? show in winbar
  header = "      " .. "                   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F"
  if show_chars then
    header = header .. "  0123456789ABCDEF"
  end
  if opts then
    opts.display_width = #header
    opts.winbar = header
  end

  --table.insert(lines, header)

  while start0 < finish do
    if start0 % 16 == 0 then
      if line ~= "" then
        line = line .. " " .. chars
        table.insert(lines, line)
        line = ""
        if show_chars then chars = "" end
      end
      line = line .. string.format("%016x  ", start0)
    end
    if start0 < start then
      line = line .. "   "
      if show_chars then chars = chars .. " " end
    else
      local c
      if type(bytes) == 'string' then
        c = bytes:byte(i)
      else
        c = bytes[i]
      end
      line = line .. string.format("%02x ", c)
      if show_chars then
        if c < 32 or c >= 127 then c = 46 end
        chars = chars .. string.char(c)
      end
      i = i + 1
    end
    start0 = start0 + 1
  end
  local trail = 16 - finish % 16
  if trail > 0 and trail < 16 then
    line = line .. string.rep("   ", trail)
  end
  if show_chars then
    line = line .. " " .. chars
  end
  table.insert(lines, line)


  return lines, nil
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

    -- Get original key mapping, like in the plugin below
    -- https://github.com/anuvyklack/keymap-amend.nvim/blob/master/lua/keymap-amend.lua
    --[[
    vim.keymap.set('n', '<PageUp>',
      function()
        print("Page Up!")
      end,
      { buffer = buffer.handle(), desc = "Scroll page up"}
    )

    vim.keymap.set('n', '<Up>',
      function()
        print("Up!")
        vim.api.nvim_feedkeys('<Up>', 'n', true)
      end,
      { buffer = buffer.handle(), desc = "Scroll up"}
    )

    vim.keymap.set('n', '<Down>',
      function()
        print("Down!")
      end,
      { buffer = buffer.handle(), desc = "Scroll down"}
    )
  ]]
  end

  vim.keymap.set('n', 'vc',
    function()
      if buffer.hex.opts.show_chars then
        buffer.hex.opts.show_chars = false
      else
        buffer.hex.opts.show_chars = true
      end
      buffer:dump()
    end,
    { buffer = buffer.handle(), desc = "Show/hide characters"}
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

    --TODO: first set start and size in options, then do buffer:dump()
    M.dump(buffer, from, size)
  end

  --TODO: Move cursor in GUI to the specified address
end

local function dump(buffer)
  M.dump(buffer, buffer.hex.from, buffer.hex.size, buffer.hex.opts)
end

M.dump = function(buffer, from, size_or_bytes, opts)
  local bytes
  local size
  local fixed = false

  if buffer == nil then
    error("Buffer is nil for hex dump")
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
        error(string.format("Size of memory to dump cannot be negative, size=[%d]", size))
      end

      if size > M.maxsize then
        size = M.maxsize
        print(string.format("Dump size truncated to %d bytes", M.maxsize))
      end
      bytes = M.mem.read(from, size)

    else
      error(string.format("Dump expects either a fixed byte string, or an address and size"))
    end
  end

  --TODO: Change .hex to .dis, or call it abstractly .mem? Or just buffer.opts?
  if buffer.hex == nil then
    buffer.hex = {}
  end
  buffer.hex.opts = opts or {}
  buffer.hex.opts.fixed = fixed

  local lines, highlight = M.hex(from, bytes, buffer.hex.opts)
  buffer.update(lines, highlight)

  if buffer.hex.opts.show_chars == nil then
    buffer.hex.opts.show_chars = true
  end
  buffer.hex.from = from
  buffer.hex.size = size
  if not fixed then
    buffer.hex.mem = M.mem
    buffer.jump = jump
  end
  buffer.dump = dump

  setup_keymaps(buffer)
end

return M

