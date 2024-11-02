-- References, cross-references, names, labels, ...
local M = {}

M.sym = {}

-- Datatype
-- data = false | true
-- skip = true if value needs not be displayed (unused space)
-- count = #
-- size = #bytes
-- name = name / menmonics / data type name etc
-- decimal = true | (false|nil)
-- binary = true | (false|nil)
-- signed = true | (false|nil)
-- ref = true | false if value is a code/data reference
M.datatype = {}

M.label = function(addr, label, datatype)
  M.sym[addr] = label
  if datatype ~= nil then
    M.datatype[addr] = datatype
  end
end

M.by_label = function(label)
  for addr, l in pairs(M.sym) do
    if l == label then
      return addr
    end
  end

  return nil
end

return M
