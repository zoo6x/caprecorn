-- String used as a byte buffer

--TODO: Big endian will not work this way
string.from = function(src, bytes)
  if type(src) == 'string' then
    return src
  end
  if type(src) == 'number' then
    if bytes == nil then
      bytes = 1
    end
    local res = ""
    for i = 1, bytes do
      local b = src % 256
      src = src / 256
      local c = string.char(b)
      res = res .. c
    end
    return res
  end
  if type(src) == 'table' then
    if bytes == nil then
      bytes = 1
    end
    local res = ""
    for i = 1, #src do
      local v = src[i]
      res = res .. string.from(v, bytes)
    end
    return res
  end
  error(string.format("Cannot convert to string from value=[%s] type=[%s]", tostring(src), type(src)))
end

string.prepend = function(dst, src, bytes)
  return string.from(src, bytes) .. dst
end

string.append = function(dst, src, bytes)
  return dst .. string.from(src, bytes)
end

-- Extracts big-endian value from a byte string
-- Index is 0-based
string.bytes_be = function(s, pos, count)
  local res = 0
  local till = pos + 1 + count
  local size = #s
  if till > size then
    till = size
  end
  for i = pos + 1, till do
    local c = s:sub(i, i)
    local b = string.byte(c)
    res = res * 256 + b
  end

  return res
end

string.bytes_le = function(s, pos, count)
  if pos == nil then
    pos = 0
  end
  local res = 0
  local till = pos + count
  local size = #s
  if till > size then
    till = size
  end
  local scale = 1
  for i = pos + 1, till do
    local c = s:sub(i, i)
    local b = string.byte(c)
    res = res + b * scale
    scale = scale * 256
  end

  return res
end

string.i8 = function(s, ofs)
  return s:bytes_le(ofs, 1)
end

string.i16 = function(s, ofs)
  return s:bytes_le(ofs, 2)
end

string.i32 = function(s, ofs)
  return s:bytes_le(ofs, 4)
end

string.i64 = function(s, ofs)
  return s:bytes_le(ofs, 8)
end

