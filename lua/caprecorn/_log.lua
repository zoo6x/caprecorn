-- Text log file to debug the plugin crashes
local M = {}

local filename = "./caprecorn.log"

local file = io.open(filename, "w+")
file:close()

local enabled = true

M.off = function ()
  enabled = false
end

M.on = function ()
  enabled = true
end

M.writen = function(line)
  if not enabled then
    return
  end
  file = io.open(filename, "a+")
  file:write(line)
  file:close()
end

M.write = function(line)
  M.writen(line)
  M.writen("\n")
end

return M
