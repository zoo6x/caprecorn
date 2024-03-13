-- Syscalls etc
local M = {}

-- https://stackoverflow.com/questions/38751614/what-are-the-return-values-of-system-calls-in-assembly

M.mmap_addr = nil

local _log = require("_log")

local arch = require("arch")
M.arch = arch.arch

local hex = require("hex")
-- Set by Unicorn on open()
M.mem = nil
M.reg = nil

local EPERM =           1
local ENOENT =          2
local ESRCH =           3
local EINTR =           4
local EIO =             5
local ENXIO =           6
local E2BIG =           7
local ENOEXEC =         8
local EBADF =           9
local ECHILD =         10
local EAGAIN =         11
local ENOMEM =         12
local EACCES =         13
local EFAULT =         14
local ENOTBLK =        15
local EBUSY =          16
local EEXIST =         17
local EXDEV =          18
local ENODEV =         19
local ENOTDIR =        20
local EISDIR =         21
local EINVAL =         22
local ENFILE =         23
local EMFILE =         24
local ENOTTY =         25
local ETXTBSY =        26
local EFBIG =          27
local ENOSPC =         28
local ESPIPE =         29
local EROFS =          30
local EMLINK =         31
local EPIPE =          32
local EDOM =           33
local ERANGE =         34

local AT_FDCWD = 0xffffff9c

local PAGESIZE = 4096

local ARCH_SET_GS	= 0x1001
local ARCH_SET_FS	=	0x1002
local ARCH_GET_FS	=	0x1003
local ARCH_GET_GS	=	0x1004

-- Helper functions

local function align(addr, size)
  return addr - addr % size
end

local function align_up(addr, size)
  if addr % size == 0 then
    return addr
  else
    return align(addr + size, size)
  end
end

local function mem_read_cstring(addr)
  local res = ""
  while true do
    local status, b = M.mem.read_safe(addr, 1)
    if status == false then
      _log.write(b)
      return nil
    end
    b = b:sub(1, 1)
    if b == '\000' then break end
    res = res .. b
    addr = addr + 1
  end
  return res
end

-- Open files
M.fds = {
  last_fd = 2,
}

-- Syscall handlers

local function sys_read(fd, p_buf, count)
  local fd_info

  fd_info = M.fds[fd]
  if fd_info == nil then
    return -EINVAL
  end

  _log.write(string.format("Reading %d bytes from file name=[%s]", count, fd_info.name))
  local status, bytes = pcall(fd_info.file.read, fd_info.file, count)
  if status == false then
    _log.write(string.format("Read error [%s]", tostring(bytes)))
  end
  _log.write(string.format("Read %d bytes", #bytes))
  local dump = hex.hex(p_buf, bytes, { show_chars = true })
  for _, line in ipairs(dump) do
    _log.write(line)
  end

  local status, error = M.mem.write(p_buf, bytes)
  if status == false then
    _log.write(string.format("Memory write error [%s]", error))
    return nil, true
  end

  return #bytes
end

local function sys_write(fd, p_buf, count)
  local status, bytes = M.mem.read_safe(p_buf, count)

  if status == false then
    _log.write(string.format("Memory read error [%s]", bytes))
    return nil, true
  end

  local fd_info
  local file
  local filename

  if fd == 1 then
    filename = "<stdout>"
    file = io.stdout
  elseif fd == 2 then
    filename = "<stderr>"
    file = io.stderr
  else
    fd_info = M.fds[fd]
    if fd_info == nil then
      return -EINVAL
    end

    filename = fd_info.name
    file = fd_info.file
  end

  _log.write(string.format("Writing %d bytes to file name=[%s]", count, filename))
  local dump = hex.hex(p_buf, bytes, { show_chars = true })
  for _, line in ipairs(dump) do
    _log.write(line)
  end

  if fd == 1 or fd == 2 then
    -- This damages Nvim UI
    -- TODO: write to output log (repl style). Also need input from repl
    --file:write(bytes)
  else
    _log.write(string.format("Ignoring write attempt to file name [%s] until whitelisted", filename))
  end

  return #bytes
end

local function sys_close(fd)
  local fd_info

  fd_info = M.fds[fd]
  if fd_info == nil then
    return -EINVAL
  end

  _log.write(string.format("Closing file name=[%s]", fd_info.name))
  local status, message = pcall(fd_info.file.close, fd_info.file)
  if status == false then
    _log.write(string.format("Close error [%s]", tostring(message)))

    return -EFAULT
  end

  M.fds[fd] = nil

  return 0
end

local function sys_stat(p_filename,	p_statbuf)
  local filename = mem_read_cstring(p_filename)
  _log.write(string.format("stat filename=[%s] statbuf=%016x", filename, p_statbuf))
  return -EPERM
end

local function sys_fstat(fd, p_statbuf)
  local fd_info

  fd_info = M.fds[fd]
  if fd_info == nil then
    return -EINVAL
  end

  local current = fd_info.file:seek()
  local size = fd_info.file:seek("end")
  fd_info.file:seek("set", current)

  _log.write(string.format("fstat filename=[%s] statbuf=%016x file size=%d", filename, p_statbuf, size))

  -- struct stat size is 144 bytes
  -- st_size is at offset 48, a 64-bit integer 
  local bytes = string.rep('\000', 48)
  bytes = bytes:append(string.from(size, 8))
  bytes = bytes:rpadtrunc(144, '\000')

  local status, error = M.mem.write(p_statbuf, bytes)
  if status == false then
    _log.write(string.format("mem_write error [%s]", error))
    return nil, true
  end

  return 0
end

local function sys_brk(brk)
  if brk == 0 then
    return M.emu.brk_addr
  end

  local cur_brk_addr = M.emu.brk_address
  local new_brk_addr = align_up(brk, PAGESIZE)

  if new_brk_addr > cur_brk_addr then
    M.mem.map(cur_brk_addr, new_brk_addr - cur_brk_addr)
  elseif new_brk_addr < cur_brk_addr then
    M.mem.unmap(new_brk_addr, cur_brk_addr - new_brk_addr)
  end

  M.emu.brk_addr = new_brk_addr

  return M.emu.brk_addr
end

local function sys_pread64(fd, p_buf, count, pos)
  local fd_info

  fd_info = M.fds[fd]
  if fd_info == nil then
    return -EINVAL
  end

  _log.write(string.format("Reading %d bytes at position %d from file name=[%s]", count, pos, fd_info.name))
  
  local status, bytes

  status, _ = pcall(fd_info.file.seek, fd_info.file, "set", pos)
  if status == false then
    _log.write(string.format("Seek error [%s]", tostring(pos)))
    return -EFAULT
  end
  local current = fd_info.file:seek()
  _log.write(string.format("Current pos = %d", current))

  status, bytes = pcall(fd_info.file.read, fd_info.file, count)
  if status == false then
    _log.write(string.format("Read error [%s]", tostring(bytes)))
  end
  _log.write(string.format("Read %d bytes", #bytes))
  local dump = hex.hex(p_buf, bytes, { show_chars = true })
  for _, line in ipairs(dump) do
    _log.write(line)
  end

  local status, error = M.mem.write(p_buf, bytes)
  if status == false then
    _log.write(string.format("mem_write error [%s]", error))
    return nil, true
  end

  return #bytes
end

local function sys_mmap(addr, len, prot, flags, fd, off)
  if fd ~= 0xffffffff then
    if M.fds[fd] == nil then
      _log.write(string.format("mmap failed due to unknown fd=%d", fd))
      return -EINVAL
    end
  end

  if addr == 0 then
    addr = align(M.mmap_addr - len, PAGESIZE)
  end

  --TODO: flags, prot...
  local size = align_up(len, PAGESIZE)
  _log.write(string.format("Mapping %x bytes at address %016x", size, addr))
  local status, error = M.mem.map_safe(addr, size)
  if status == false then
    _log.write(string.format("mmap failed, error=[%s]", error))
    return -EFAULT
  end

  M.mmap_addr = addr

  if fd ~= 0xffffffff then
    sys_pread64(fd, addr, len, off)
    --TODO: W/a error, or incomplete data? Ignore for now
  end

  return addr
end

local function sys_mprotect(start, len, prot)
  return 0
end

local function sys_munmap(addr, len)
  return 0
end

local function sys_writev(fd, p_iovec, value_index)
  return 0
end

local function sys_access(p_filename, mode)
  return -ENOENT
end

local function sys_exit(exit_code)
  return nil, true, exit_code
end

local function sys_uname(p_buf)
  local UTSLEN = 65

  local fields = {
    --[[
    --TODO: Why does this uname cause exit_group?

    'MurdozeOS',                -- sysname
    'murdoze',                  -- nodename
    '0.0.1-RELEASE',            -- release
    'MurdozeOS 0.1.0-dev r1',   -- version
    'machindoze',               -- machine
    '',                         -- domainname
    ]]
        'QilingOS',
        'ql_vm',
        '99.0-RELEASE',
        'QilingOS 99.0-RELEASE r1',
        'ql_processor',
        ''
  }

  for i, s in ipairs(fields) do
    local field = string.rpadtrunc(s, UTSLEN, '\000')
    _log.write(string.format("uname field [%s]", field))
    M.mem.write(p_buf + (i - 1) * UTSLEN, field)
  end

  return 0
end

local function sys_arch_prctl(code, addr)

  if code == ARCH_SET_FS then
    _log.write(string.format("arch_prctl ARCH_SET_FS addr=%016x", addr))

    local msr_value = string.from({ 0xc0000100, addr}, 8)
    M.reg.write_buf(M.reg.x86.msr, msr_value)

    return 0
  end

  return -EINVAL
end

local function sys_openat(dir_fd, p_filename, flags, mode)
  local filename = mem_read_cstring(p_filename)
  _log.write(string.format("openat dir_fd=%d filename=[%s] flags=%x mode=%x", dir_fd, filename, flags, mode))

  if dir_fd ~= AT_FDCWD then
    return -EINVAL
  end

  --if filename == "/etc/ld.so.cache" then
  --  return -ENOENT
  --end

  local file = io.open(filename, "r")
  if file == nil then
    return -ENOENT
  end

  local fd = M.fds.last_fd + 1
  local fd_info = {
    name = filename,
    file = file,
  }
  M.fds[fd] = fd_info

  return fd
end

M.syscall = {
  [M.arch.X86_64] = {
    [0]   = { handler = sys_read, name = "read", params = 3, },
    [1]   = { handler = sys_write, name = "write", params = 3, },
    [3]   = { handler = sys_close, name = "close", params = 1, },
    [4]   = { handler = sys_stat, name = "stat", params = 2, },
    [5]   = { handler = sys_fstat, name = "fstat", params = 2, },
    [9]   = { handler = sys_mmap, name = "mmap", params = 6, },
    [10]  = { handler = sys_mprotect, name = "mprotect", params = 3, },
    [11]  = { handler = sys_munmap, name = "munmap", params = 2, },
    [12]  = { handler = sys_brk, name = "brk", params = 1, },
    [17]  = { handler = sys_pread64, name = "pread64", params = 4, },
    [20]  = { handler = sys_writev, name = "writev", params = 3, },
    [21]  = { handler = sys_access, name = "access", params = 2, },
    [60]  = { handler = sys_exit, name = "exit", params = 1, },
    [63]  = { handler = sys_uname, name = "uname", params = 1, },
    [158] = { handler = sys_arch_prctl, name = "arch_prctl", params = 2, },
    [231] = { handler = sys_exit, name = "exit_group", params = 1, },
    [257] = { handler = sys_openat, name = "openat", params = 4, },
  }
}

return M

