-- Memory mapping

local M = {}

local _log = require("_log")

M.setup = function(engine)
  M._engine = engine
end

M.PAGESIZE = 4096

M.align = function(addr, size)
  return addr - addr % size
end

M.align_up = function(addr, size)
  if addr % size == 0 then
    return addr
  else
    return M.align(addr + size, size)
  end
end

M.map_safe = function(from, size, prot)
  if prot == nil then
    prot = 7 -- rwx
  end
  --_log.write(string.format("MEMORY MAP address = %016x - %016x size = %x", from, from + size, size))

  local regions = M._engine:mem_regions()
  table.sort(regions, function(r1, r2) return r1.begins < r2.begins end)
  for i, region in ipairs(regions) do
    -- _log.write(string.format("Region %5d address = %016x - %016x size = %x", i, region.begins, region.ends, region.ends - region.begins))
    local lbound = region.begins
    local ubound = M.align_up(region.ends, M.PAGESIZE)
    if from < ubound and from + size > lbound then
      lbound = math.max(from, lbound)
      ubound = math.min(from + size, ubound)

      M.unmap(lbound, ubound - lbound)
    end
  end

  return M._engine:mem_map(from, size, prot)
end

M.map = function(from, size, prot)
  local status, err = M.map_safe(from, size, prot)

  if not status then
    error(string.format("Error [%s] when trying to map %d bytes at address %016x", err, size, from))
  end
end

M.unmap = function(from, size)
  -- _log.write(string.format("MEMORY UNMAP address = %016x - %016x size = %x", from, from + size, size))
  local status, err = M._engine:mem_unmap(from, size)

  if not status then
    error(string.format("Error [%s] when trying to unmap %d bytes at address %016x", err, size, from))
  end
end

M.read_safe = function(from, size)
  if from == nil or size == nil then
    return false, string.format("Invalid parameters for mem_read from=[%s] size=[%s]", tostring(from), tostring(size))
  end

  local status, bytes_or_message = M._engine:mem_read(from, size)

  if not status then
    bytes_or_message = string.format("Error [%s] when trying to read %d bytes from address 0x%x", bytes_or_message, size, from)
  end

  return status, bytes_or_message
end

M.read = function(from, size)
  if from == nil or size == nil then
    error(string.format("Invalid parameters for mem_read from=[%s] size=[%s]", tostring(from), tostring(size)))
  end

  local status, bytes_or_message = M._engine:mem_read(from, size)

  if not status then
    error(string.format("Error [%s] when trying to read %d bytes from address 0x%x", bytes_or_message, size, from))
  end

  return bytes_or_message
end

M.write = function(from, bytes)
  local status, err = M._engine:mem_write(from, bytes)
  if not status then
    error(string.format("Memory write error=[%s]", err))
  end
end

return M

