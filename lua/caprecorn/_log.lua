-- Text log file to debug the plugin crashes
local M = {}

local filename = "./caprecorn.log"

local file = io.open(filename, "w+")
file:close()

M.write = function(line)
  file = io.open(filename, "a+")
  file:write(line, "\n")
  file:close()
end

return M
