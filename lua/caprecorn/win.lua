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
  local current_tab_handle = vim.api.nvim_tabpage_get_number(0)
  M.current_win_handle = vim.api.nvim_tabpage_get_win(current_tab_handle)
end

M.end_layout = function()
  if M.current_win_handle ~= nil then
    --TODO: check when this function is available in release
    --vim.api.nvim_tabpage_set_win(current_tab_handle, current_win_handle)
    vim.fn.win_gotoid(M.current_win_handle)
    M.current_win_handle = nil
  end
end

M.wrap = function(win_handle)
  local window = {
    handle = function()
      return win_handle
    end,

    close = function()
      vim.api.nvim_win_hide(win_handle)

      for i = 1, #M.windows do
        if M.windows[i].handle() == win_handle then
          table.remove(M.windows, i)
          break
        end
      end
    end,

    split = function()
      vim.cmd.split({ mods = { horizontal = true } })

      return M.wrap(current_win_hanle())
    end,

    vsplit = function()
      vim.cmd.vsplit({ mods = { vertical = true } })

      return M.wrap(current_win_hanle())
    end,
  }

  table.insert(M.windows, window)

  return window
end

M.tab = function()
  vim.cmd.tabnew()
  local win_handle = vim.fn.win_getid()

  local window = M.wrap(win_handle)

  return window
end

M.new = function()
end

return M
