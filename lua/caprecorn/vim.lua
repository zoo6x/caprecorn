-- Vim integration

local M = {}

M.setup = function()
  if vim == nil then
    return
  end

  -- Load Lua files in NVim with Caprecorn
  vim.api.nvim_create_autocmd("BufEnter", {
    pattern = {"*.caprecorn.lua"},
    callback = function(args)
      local dir = vim.fn.fnamemodify(args.file, ':p:h')
      local path = dir .. "/?.lua"
      if string.find(package.path, path) == nil then
        package.path = path .. ";" .. package.path
      end
      vim.keymap.set('n', 'LL',
        function()
          vim.cmd("w")

          if M.close ~= nil then
            M.close()
          end

          vim.cmd("source " .. args.file)
        end,
        { buffer = args.buf, desc = "Load Lua file"}
      )
    end
  })
end

-- How to configure plugin for development
-- See ~/.config/nvim/init.lua
--[[
-- Development
local plugin_path = "/home/john/src/caprecorn"
vim.opt.rtp:prepend(plugin_path)
package.cpath = plugin_path .. "/lib/?.so;" .. package.cpath
package.path = plugin_path .. "/lua/caprecorn/?.lua;" .. package.path
require("caprecorn")
local loaded, caprecorn = pcall(require, 'caprecorn')
if loaded then
  _G["caprecorn"] = caprecorn
end
--]]

return M
