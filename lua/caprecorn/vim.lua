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
      print("Caprecorn file open!", args.match, args.buf, args.file)
      local dir = vim.fn.fnamemodify(args.file, ':p:h')
      local path = dir .. "/?.lua"
      if string.find(package.path, path) == nil then
        package.path = path .. ";" .. package.path
      end
      vim.keymap.set('n', 'LL',
        function()
          if M.close ~= nil then
            M.close()
          end
          print("Loading Lua file " .. args.file);
          vim.cmd("w")
          vim.cmd("source " .. args.file)
        end,
        { buffer = args.buf, desc = "Load Lua file"}
      )
    end
  })
end

return M
