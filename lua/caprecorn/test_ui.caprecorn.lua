-- Vim UI integration tests

local C = require('caprecorn')

C.win.begin_layout()

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

C.win.end_layout()


buf2.update({"Text 1", "Text 2"})
tab1.buf(buf2)
tab2s.buf(buf2)
tab2sv.buf(buf2)
