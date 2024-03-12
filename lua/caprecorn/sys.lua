-- Syscalls etc
local M = {}

-- https://stackoverflow.com/questions/38751614/what-are-the-return-values-of-system-calls-in-assembly

local arch = require("arch")
M.arch = arch.arch

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

-- Syscall handlers

local function sys_mmap(addr, len, prot, flags, fd, off)
  -- See syscall_mmap_impl() in Qiling

  -- Have a stack segment, baby
  return 0x00007ffffffde000
end

local PAGESIZE = 4096

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

local function sys_writev(fd, p_iovec, value_index)
  return 0
end

local function sys_exit(exit_code)
  return nil, true, exit_code
end

local function sys_arch_prctl(p_task, code, p_addr)
  return -EPERM
end

M.syscall = {
  [M.arch.X86_64] = {
    [9]   = { handler = sys_mmap, name = "mmap", params = 6, },
    [12]  = { handler = sys_brk, name = "brk", params = 1, },
    [20]  = { handler = sys_writev, name = "writev", params = 3, },
    [60]  = { handler = sys_exit, name = "exit", params = 1, },
    [158] = { handler = sys_arch_prctl, name = "arch_prctl", params = 3, },
    [231] = { handler = sys_exit, name = "exit_group", params = 1, },
  }
}

return M

