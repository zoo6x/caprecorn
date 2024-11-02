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

    go_to_address_func = function(buffer)
      return function()
        local addr

        local row = vim.api.nvim_win_get_cursor(0)[1]
        local tag = (buffer.hex.tags or {})[row]

        vim.fn.inputsave()
        local addr_str = vim.fn.input("Input address or +/-offset:")
        vim.fn.inputrestore()
        if addr_str == "" then
          return
        end
        addr_str = addr_str:gsub("%s+", "")
        if #addr_str == 0 then return end
        local sign = string.sub(addr_str, 1, 1)

        if sign == "+" or sign == "-" then
          addr = tonumber(addr_str)
          if addr == nil then
            print("Invalid relative offset")
            return
          end
          addr = tag.addr + addr
        else
          local addr_str_hex = "0x" .. addr_str
          addr = tonumber(addr_str_hex)

          if addr == nil then
            local reg_id = M.reg.by_name(addr_str)
            if reg_id ~= nil then
              local reg_value = M.reg.read(reg_id)
              if reg_value ~= nil then
                addr = reg_value
              else
                print("Failed to read register register")
                return
              end
            else
              local label_addr = M.ref.by_label(addr_str)
              if label_addr ~= nil then
                addr = label_addr
              else
                print("Invalid hex address, register or label name")
                return
              end
            end
          end
        end

        if buffer.hex.jump_history == nil then
          buffer.hex.jump_history = {}
        end
        table.insert(buffer.hex.jump_history, tag.addr)

        buffer:jump(addr)
      end
    end
  }

  table.insert(M.buffers, buffer)

  return buffer
end

return M

