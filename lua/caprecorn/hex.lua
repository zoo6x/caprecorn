-- Hexadecimal dump viewer and editor

local M = {}

-- TODO: opt.chars - showcharacters, otherwise hex dump only
-- User should be allowed to switch this from the UI
-- Returns: lines, highlight
M.hex = function (start, bytes, opt)
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

--[[  
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
      --TODO: need an open engine here to read memory!
    end,
    { buffer = buf_handle, desc = "Go to address"}
  )
  ]]

  return lines, nil
end


return M

