-- Vim UI integration tests

local C = require('caprecorn')

C.win.begin_layout()

local tab1 = C.win.tab()
local buf0 = C.buf.new("buf0")


local tab2 = C.win.tab()

local buf1 = C.buf.new("buf1")
local buf2 = C.buf.new("buf2")


C.win.end_layout()


buf2.update({"Text 1", "Text 2"})
