-- Vim buffers

local M = {}

-- Highlight
M.highlight_namespace = vim.api.nvim_create_namespace("caprecorn")

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

      vim.api.nvim_buf_clear_namespace(buf_handle, M.highlight_namespace, 0, -1)

      vim.api.nvim_buf_set_lines(buf_handle, 0, -1, false, lines)

      -- Highlight
      if highlight ~= nil then
        for i = 1, #highlight do
          local hl = highlight[i]
          if hl.highlights ~= nil then
            for _, hl_addr in ipairs(hl.highlights) do
              local line = hl_addr.line
              local start_col = hl_addr.start_col
              hl_addr.strict = false
              hl_addr.line = nil
              hl_addr.start_col = nil
              vim.api.nvim_buf_set_extmark(
                buf_handle, M.highlight_namespace,
                line,
                start_col,
                hl_addr)
              hl_addr.line = line
              hl_addr.start_col = start_col
                --[[
                {
                  strict = false,
                  end_col = hl_addr.end_col,
                  hl_group = hl_addr.group,
                  virt_lines_above = true,
                  virt_lines = {{
                    { "func_1:", 'CrcDisTarget' },
                  }},
                  -- virt_text = {{'Jump', 'CrcDisJump'}, {'Call', 'CrcDisCall'}},
                }
                ]]
            end
          end
        end
      end

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

