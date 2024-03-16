-- Syscalls etc
local M = {}

-- https://stackoverflow.com/questions/38751614/what-are-the-return-values-of-system-calls-in-assembly

-- sys_rseq
-- https://www.efficios.com/blog/2019/02/08/linux-restartable-sequences/

M.mmap_addr = nil

local _log = require("_log")

-- Dump read/write buffers to the log file
M.log_dump = false


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

local function log_dump(addr, bytes)
  if M.log_dump == false then return end

  local dump = hex.hex(addr, bytes, { show_chars = true })
  for _, line in ipairs(dump) do
    _log.write(line)
  end
end

-- Open files
M.fds = {
  last_fd = 2,
}

-- Syscall handlers

local function sys_read(fd, p_buf, count)
  _log.writen(string.format("read(%d, 0x%016x, %d) = ", fd, p_buf, count))

  local fd_info

  fd_info = M.fds[fd]
  if fd_info == nil then
  _log.write(-EINVAL)
    return -EINVAL
  end

  --_log.write(string.format("Reading %d bytes from file name=[%s]", count, fd_info.name))
  local status, bytes = pcall(fd_info.file.read, fd_info.file, count)
  if status == false then
    --_log.write(string.format("Read error [%s]", tostring(bytes)))
  end
  --_log.write(string.format("Read %d bytes", #bytes))
  log_dump(p_buf, bytes)

  local status, error = M.mem.write(p_buf, bytes)
  if status == false then
    _log.write(string.format("Memory write error [%s]", error))
    return nil, true
  end

  _log.write(#bytes)
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

  --_log.write(string.format("Writing %d bytes to file name=[%s]", count, filename))
  --log_dump(p_buf, bytes)

  if fd == 1 or fd == 2 then
    -- This damages Nvim UI
    -- TODO: write to output log (repl style). Also need input from repl
    --file:write(bytes)
    _log.writen(bytes)
  else
    _log.write(string.format("Ignoring write attempt to file name [%s] until whitelisted", filename))
  end

  return #bytes
end

local function sys_close(fd)
  _log.writen(string.format("close(%d) = ", fd))
  local fd_info

  fd_info = M.fds[fd]
  if fd_info == nil then
    _log.write(-EINVAL)
    return -EINVAL
  end

  -- _log.write(string.format("Closing file name=[%s]", fd_info.name))
  local status, message = pcall(fd_info.file.close, fd_info.file)
  if status == false then
    _log.write(string.format("Close error [%s]", tostring(message)))

    _log.write(-EFAULT)
    return -EFAULT
  end

  M.fds[fd] = nil
  if M.fds.last_fd == fd then
    M.fds.last_fd = M.fds.last_fd - 1
  end

  _log.write(0)
  return 0
end

-- See here https://github.com/luapower/fs/blob/master/fs_posix.lua
local function sys_stat(p_filename,	p_statbuf)
  local filename = mem_read_cstring(p_filename)
  _log.write(string.format("stat filename=[%s] statbuf=%016x", filename, p_statbuf))
  return -EPERM
end

local function sys_fstat(fd, p_statbuf)
  _log.writen(string.format("fstat(%d, %016x) = ", fd, p_statbuf))
  local fd_info

  fd_info = M.fds[fd]
  if fd_info == nil then
    _log.write(-EINVAL)
    return -EINVAL
  end

  local current = fd_info.file:seek()
  local size = fd_info.file:seek("end")
  fd_info.file:seek("set", current)

  -- _log.write(string.format("fstat filename=[%s] statbuf=%016x file size=%d", fd_info.name, p_statbuf, size))

  -- struct stat size is 144 bytes
  -- st_size is at offset 48, a 64-bit integer 
  local bytes = string.rep('\000', 48)
  bytes = bytes:append(string.from(size, 8)) -- st_size
  bytes = bytes:append(string.from(4096, 8)) -- st_blksize 
  bytes = bytes:append(string.from(math.floor(size / 512), 8)) -- st_blocks
  bytes = bytes:rpadtrunc(144, '\000')

  if fd_info.name == "/usr/local/lib/libc.so.6" then
    bytes = "\002\008\000\000\000\000\000\000\123\149\080\000\000\000\000\000\001\000\000\000\000\000\000\000\253\129\000\000\232\003\000\000\232\003\000\000\000\000\000\000\000\000\000\000\000\000\000\000\136\087\175\000\000\000\000\000\000\016\000\000\000\000\000\000\176\087\000\000\000\000\000\000\046\002\244\101\000\000\000\000\195\061\200\021\000\000\000\000\140\000\244\101\000\000\000\000\158\252\215\013\000\000\000\000\043\002\244\101\000\000\000\000\020\057\091\025\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"    
  end

  if fd_info.name == "/etc/ld.so.cache" then
    bytes = "\002\008\000\000\000\000\000\000\096\001\120\000\000\000\000\000\001\000\000\000\000\000\000\000\164\129\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\207\068\002\000\000\000\000\000\000\016\000\000\000\000\000\000\040\001\000\000\000\000\000\000\101\038\243\101\000\000\000\000\029\034\093\023\000\000\000\000\212\182\241\101\000\000\000\000\050\059\216\034\000\000\000\000\235\204\241\101\000\000\000\000\052\116\116\032\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
  end

  log_dump(p_statbuf, bytes)

  local status, error = M.mem.write(p_statbuf, bytes)
  if status == false then
    _log.write(string.format("mem_write error [%s]", error))
    return nil, true
  end

  _log.write(0)
  return 0
end

local function sys_brk(brk)
  if brk == 0 then
    return M.emu.brk_addr
  end

  local cur_brk_addr = M.emu.brk_address
  local new_brk_addr = M.mem.align_up(brk, M.mem.PAGESIZE)

  if new_brk_addr > cur_brk_addr then
    M.mem.map(cur_brk_addr, new_brk_addr - cur_brk_addr)
  elseif new_brk_addr < cur_brk_addr then
    M.mem.unmap(new_brk_addr, cur_brk_addr - new_brk_addr)
  end

  M.emu.brk_addr = new_brk_addr

  return M.emu.brk_addr
end

local function sys_pread64(fd, p_buf, count, pos)
  _log.writen(string.format("pread64(%d, 0x%016x, %d, %d) = ", fd, p_buf, count, pos))

  local fd_info

  fd_info = M.fds[fd]
  if fd_info == nil then
    _log.write(-EINVAL)
    return -EINVAL
  end

  --_log.write(string.format("Reading %d bytes at position %d from file name=[%s]", count, pos, fd_info.name))

  local status, bytes

  status, _ = pcall(fd_info.file.seek, fd_info.file, "set", pos)
  if status == false then
    -- _log.write(string.format("Seek error [%s]", tostring(pos)))
    _log.write(-EFAULT)
    return -EFAULT
  end
  local current = fd_info.file:seek()
  --_log.write(string.format("Current pos = %d", current))

  status, bytes = pcall(fd_info.file.read, fd_info.file, count)
  if status == false then
    _log.write(string.format("Read error [%s]", tostring(bytes)))
  end
  --_log.write(string.format("Read %d bytes", #bytes))
  log_dump(p_buf, bytes)

  local status, error = M.mem.write(p_buf, bytes)
  if status == false then
    _log.write(string.format("mem_write error [%s]", error))
    return nil, true
  end

  _log.write(#bytes)
  return #bytes
end

local function sys_mmap(addr, len, prot, flags, fd, off)
  _log.writen(string.format("mmap(0x%016x, 0x%x, 0x%x, 0x%x, %d, 0x%x) = ", addr, len, prot, flags, fd, off))

  local res = addr

  if fd ~= 0xffffffff then
    if M.fds[fd] == nil then
      -- _log.write(string.format("mmap failed due to unknown fd=%d", fd))
      _log.write(-EINVAL)
      return -EINVAL
    end
  end

  if addr == 0 then
    addr = M.mem.align(M.mmap_addr - len, PAGESIZE)

    M.mmap_addr = addr
  end

  --TODO: flags, prot...
  local size = M.mem.align_up(len, PAGESIZE)
  -- _log.write(string.format("Mapping %x bytes at address %016x", size, addr))
  local status, error = M.mem.map_safe(addr, size)
  if status == false then
    --_log.write(string.format("mmap failed, error=[%s]", error))
    _log.write(-EFAULT)
    return -EFAULT
  end

  if fd ~= 0xffffffff then
    _log.off()
    sys_pread64(fd, addr, len, off)
    _log.on()
    --TODO: W/a error, or incomplete data? Ignore for now
  end

  _log.write(string.format("%016x", addr))
  return addr
end

local function sys_mprotect(start, len, prot)
  _log.writen(string.format("mprotect(0x%016x, %d, %d) = ", start, len, prot))

  _log.write(0)
  return 0
end

local function sys_munmap(addr, len)
  return 0
end

local function sys_writev(fd, p_iov, count)
  local res = 0
   -- struct iov size=16
   --_log.write(string.format("Reading iov addr=%016x count=%d", p_iov, count))
  local status, vectors = M.mem.read_safe(p_iov, count * 16)

  if status == false then
    _log.write(string.format("Memory read error [%s]", vectors))
    return nil, true
  end

  for i = 0, count - 1 do
    local addr = vectors:i64(i * 16 + 0)
    local size = vectors:i64(i * 16 + 8)

    --_log.write(string.format("Writing iov %2d addr=%016x size=%x", i + 1, addr, size))

    local cur_log_dump = M.log_dump
    M.log_dump = true
    res = sys_write(fd, addr, size)
    M.log_dump = cur_log_dump 

    if res < 0 then
      break
    end
  end

  return 0
end

local function sys_access(p_filename, mode)
  local filename = mem_read_cstring(p_filename)
  _log.writen(string.format('access("%s", %x) = ', filename, mode))

  _log.write(-ENOENT)
  return -ENOENT
end

local function sys_getpid()
  --_log.writen(string.format("getpid() = "))

  --_log.write(100000)
  return 100000
end

local function sys_exit(exit_code)
  return nil, true, exit_code
end

local function sys_uname(p_buf)
  _log.writen(string.format("uname(0x%016x) = ", p_buf))

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
    --_log.write(string.format("uname field [%s]", field))
    M.mem.write(p_buf + (i - 1) * UTSLEN, field)
  end

  _log.write(0)
  return 0
end

local function sys_arch_prctl(code, addr)
  _log.writen(string.format("arch_prctl(0x%x, 0x%016x) = ", code, addr))

  if code == ARCH_SET_FS then

    local msr_value = string.from({ 0xc0000100, addr}, 8)
    M.reg.write_buf(M.reg.x86.msr, msr_value)

    _log.write(0)
    return 0
  end

  _log.write(-EINVAL)
  return -EINVAL
end

local function sys_set_tid_address(p_tid)
  _log.writen(string.format("set_tid_address(0x%016x) = ", p_tid))

  _log.write(100000)
  ---return nil, true -- 100000
  return 100000
end

local function sys_openat(dir_fd, p_filename, flags, mode)
  local filename = mem_read_cstring(p_filename)
  _log.writen(string.format('openat(%d, "%s", %d, %d) = ', dir_fd, filename, flags, mode))

  if dir_fd ~= AT_FDCWD then
    _log.write(-EINVAL)
    return -EINVAL
  end

  -- if filename == "/etc/ld.so.cache" then
  --  _log.write(-ENOENT)
  --  return -ENOENT
  -- end

  filefullname = M.rootfs .. filename

  local file = io.open(filefullname, "r")
  if file == nil then
    _log.write(-ENOENT)
    return -ENOENT
  end

  local fd = M.fds.last_fd + 1
  M.fds.last_fd = fd
  local fd_info = {
    name = filename,
    file = file,
  }
  M.fds[fd] = fd_info

  _log.write(fd)
  return fd
end

local function sys_set_robust_list(p_robust_list_head, len)
  _log.writen(string.format("set_robust_list(0x%016x, %d) = ", p_robust_list_head, len))

  _log.write(0)
  return 0
end

local function sys_rseq(p_robust_list_head, len, flags, sig)
  _log.writen(string.format("rseq(0x%016x, %d, %x, %08x) = ", p_robust_list_head, len, flags, sig))

  _log.write(0)
  return 0
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
    [39]  = { handler = sys_getpid, name = "getpid", params = 0, },
    [60]  = { handler = sys_exit, name = "exit", params = 1, },
    [63]  = { handler = sys_uname, name = "uname", params = 1, },
    [158] = { handler = sys_arch_prctl, name = "arch_prctl", params = 2, },
    [218] = { handler = sys_set_tid_address, name = "set_tid_address", params = 1, },
    [231] = { handler = sys_exit, name = "exit_group", params = 1, },
    [257] = { handler = sys_openat, name = "openat", params = 4, },
    [273] = { handler = sys_set_robust_list, name = "set_robust_list", params = 2, },
    [334] = { handler = sys_rseq, name = "rseq", params = 4, },
  }
}

return M

