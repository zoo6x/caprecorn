-- Breakpoints

local M = {}

-- Breakpoint structure
-- addr = break address
-- callback = function() ... return true to break | false to continue end 
--

M.brk = {}

M.set = function(addr, callback)
  M.brk[addr] = { addr = addr, callback = callback }
end

M.delete = function(addr)
  M.brk[addr] = nil
end

return M
