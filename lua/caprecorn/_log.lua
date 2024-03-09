-- Text log file to debug the plugin crashes
local M = {}

local filename = "./caprecorn.log"

local file = io.open(filename, "w+")

M.write = function(line)
  file:write(line, "\n")
end

return M
