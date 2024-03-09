-- Registers

local M = {}

M.emu = nil

local function create_highlight()
  vim.cmd([[
  hi default CrcRegChanged gui=bold guifg=#05c5cf
  ]])
end

M.setup = function(emu)
  M.emu = emu

  create_highlight()
end

M.dump = function(buffer)
  if buffer == nil then
    error("Buffer is nil for register dump")
  end

  if buffer.hex == nil then
    buffer.hex = {}
    buffer.hex.opts = {}
    buffer.hex.opts.old_reg_values = {}
  end

  local old_reg_values = buffer.hex.opts.old_reg_values
  local reg_values = M.read(M.def)

  local lines = {}
  local highlight = {}

  local reg_ids = {}
  for reg_id, _ in pairs(M.def) do
    table.insert(reg_ids, reg_id)
  end
  table.sort(reg_ids)

  for i = 1, #reg_ids do
    local line
    local reg_id = reg_ids[i]
    local reg_name = M.def[reg_id]
    local reg_value = reg_values[i]
    local old_reg_value = old_reg_values[i]
    local changed = false

    if old_reg_value and old_reg_value ~= reg_value then
      changed = true
      line = string.format("%-5s = %016x <= %016x", reg_name, reg_value, old_reg_value)
    else
      line = string.format("%-5s = %016x", reg_name, reg_value)
    end

    table.insert(lines, line)

    local hl = { }
    if changed then
      hl.highlights = {}
      local hl_addr = {
        line = i - 1,
        start_col = 0,
        hl_group = 'CrcRegChanged',
        end_col = 24,
        priority = 90,
      }
      table.insert(hl.highlights, 1, hl_addr)
    end
    table.insert(highlight, hl)


  end

  buffer.hex.opts.old_reg_values = reg_values

  buffer.update(lines, highlight)
end

return M

