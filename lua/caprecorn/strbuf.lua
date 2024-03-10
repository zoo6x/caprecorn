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

