-- References, cross-references, names, labels, ...
local M = {}

M.sym = {}

-- Datatype
-- data = true
-- count = #
-- size = #bytes
-- decimal = true | (false|nil)
-- binary = true | (false|nil)
-- signed = true | (false|nil)
M.datatype = {}

M.label = function(addr, label, datatype)
  M.sym[addr] = label
  if datatype ~= nil then
    M.datatype[addr] = datatype
  end
end

return M
