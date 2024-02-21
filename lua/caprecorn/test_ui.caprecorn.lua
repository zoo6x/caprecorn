-- Vim UI integration tests

local C = require('caprecorn')

C.win.begin_layout()

--[[ Creating windows in the first tab (next to NVimTree does not work so well)
local cur = C.win.current()
local right = cur.vsplit()
right.width(8)
cur.focus()
local bot = cur.split()
bot.height(5)
]]

local tab1 = C.win.tab()
local buf0 = C.buf.new("buf0")
tab1.split()

local tab2 = C.win.tab()

local buf1 = C.buf.new("buf1")
local buf2 = C.buf.new("buf2")

local tab2s = tab2.split()
local tab2sv = tab2s.vsplit()
tab2.focus()
local tab2r = tab2.vsplit()
tab2.width(20)
tab2.height(5)

C.win.end_layout()

buf1.update(C.hex.hex(0x400000,
  (function() local bytes = ""; for _=1,4096 do bytes = bytes .. string.char(math.random(0,255)) end; return bytes end)()))

buf2.update({"Text 1", "Text 2"})
tab1.buf(buf2)
tab2s.buf(buf1)
tab2sv.buf(buf2)
-- bot.buf(buf1)
-- right.buf(buf2)

