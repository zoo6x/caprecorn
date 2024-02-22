-- Vim windows

local M = {}

M.tabs = {}
M.windows = {}

M.close = function()
  while #M.windows > 0 do
    local window = M.windows[1]
    window.close()
  end
end

local function current_win_hanle()
  return vim.api.nvim_tabpage_get_win(0)
end

M.begin_layout = function()
  M.current_win_handle = vim.fn.win_getid()
end

M.end_layout = function()
  if M.current_win_handle ~= nil then
    vim.fn.win_gotoid(M.current_win_handle)
    M.current_win_handle = nil
  end
end

M.wrap = function(win_handle)

  local window = {}

  window.buffer = nil

  window.handle = function()
      return win_handle
  end

  window.close = function()
      -- Window might have been closed by the user, ignore error
      pcall(vim.api.nvim_win_hide, win_handle)

      for i = 1, #M.windows do
        if M.windows[i].handle() == win_handle then
          table.remove(M.windows, i)
          break
        end
      end
  end

  window.split = function()
      vim.cmd.split({ mods = { horizontal = true } })

      return M.wrap(current_win_hanle())
  end

  window.vsplit = function()
      vim.cmd.vsplit({ mods = { vertical = true } })

      return M.wrap(current_win_hanle())
  end

  window.focus = function()
    vim.fn.win_gotoid(window.handle())
  end

  window.buf = function(buffer)
      window.buffer = buffer

      vim.api.nvim_win_set_buf(window.handle(), buffer.handle())
  end

  window.width = function(width)
    if width == nil then
      vim.api.nvim_win_get_width(window.handle())
    else
      vim.api.nvim_win_set_width(window.handle(), width)
    end
  end

  window.height = function(height)
    if height == nil then
      vim.api.nvim_win_get_height(window.handle())
    else
      vim.api.nvim_win_set_height(window.handle(), height)
    end
  end

  table.insert(M.windows, window)

  return window
end

M.current = function()
  local current_win_handle = vim.fn.win_getid()

  return M.wrap(current_win_handle)
end

M.tab = function()
  vim.cmd.tabnew()

  return M.current()
end

return M
