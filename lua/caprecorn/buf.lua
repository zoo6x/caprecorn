-- Vim buffers

local M = {}

M.buffers = {}

M.close = function()
  while #M.buffers > 0 do
    local buffer = M.buffers[1]
    buffer.close()
  end
end

M.new = function(name)
  if type(name) ~= "string" then
    error(string.format("Buffer name should be a string, name=[%s]", name))
  end

  local buf_handle = vim.fn.bufnr(name)
  if buf_handle ~= -1 then
    -- This is fine, since it might have been loaded from a session file
    -- Just use it
    -- Name clashes are unlikely, since we prefix buffer names with "caprecorn://"
  else
    buf_handle = vim.api.nvim_create_buf(true, true)
    local buf_name = "caprecorn://" .. name
    vim.api.nvim_buf_set_name(buf_handle, buf_name)
  end

  local buffer = {
    handle = function()
      return buf_handle
    end,

    name = function()
      return name
    end,

    close = function()
      vim.cmd.bwipeout(buf_handle)

      for i = 1, #M.buffers do
        if M.buffers[i].handle() == buf_handle then
          table.remove(M.buffers, i)
          break
        end
      end
    end,

    update = function(lines, highlight)
      vim.bo[buf_handle].modifiable = true
      vim.api.nvim_buf_set_lines(buf_handle, 0, -1, false, lines)
      vim.bo[buf_handle].modifiable = false
    end,

    append = function(lines, highlight)
      local line_count = vim.api.nvim_buf_line_count(buf_handle)
      vim.bo[buf_handle].modifiable = true
      vim.api.nvim_buf_set_lines(buf_handle, line_count, line_count, false, lines)
      vim.bo[buf_handle].modifiable = false
    end,
  }

  table.insert(M.buffers, buffer)

  return buffer
end

return M

