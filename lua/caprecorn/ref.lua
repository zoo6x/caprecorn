-- References, cross-references, names, labels, ...
local M = {}

M.sym = {}

M.label = function(addr, label)
  M.sym[addr] = label
end

return M
