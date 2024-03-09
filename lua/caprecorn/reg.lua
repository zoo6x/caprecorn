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

local function filter_regs(filter)
    local reg_ids = {}

    for reg_id, reg_def in pairs(M.def) do
      local matched = true
      for k, filter_value in pairs(filter) do
        local def_value = reg_def[k]
        if filter_value == false then
          if def_value == nil or def_value == false then
          else
            matched = false
            break
          end
        else
          if filter_value == def_value then
          else
            matched = false
            break
          end
        end
      end
      if matched then
        table.insert(reg_ids, reg_id)
      end
    end
    table.sort(reg_ids)

    return reg_ids
end

local function filter_regs_by_names(names)
    local reg_ids = {}

    for i = 1, #names do
      for reg_id, reg_def in pairs(M.def) do
        local reg_name = names[i]
        if reg_name == reg_def.name then
          table.insert(reg_ids, reg_id)
        end
      end
    end

    return reg_ids
end

M.dump = function(buffer, opts)
  if buffer == nil then
    error("Buffer is nil for register dump")
  end

  if buffer.opts == nil then
    buffer.opts = opts or {}
  end

  if buffer.opts.old_reg_values == nil then
    buffer.opts.old_reg_values = {}
  end

  local old_reg_values = buffer.opts.old_reg_values

  local lines = {}
  local highlight = {}

  local reg_ids
  if buffer.opts.reg_ids ~=nil then
    reg_ids = buffer.opts.reg_ids
  elseif buffer.opts.names ~= nil then
    reg_ids = filter_regs_by_names(buffer.opts.names)
    buffer.opts.reg_ids = reg_ids
  elseif buffer.opts.filter ~= nil then
    reg_ids = filter_regs(buffer.opts.filter)
    buffer.opts.reg_ids = reg_ids
  else
    reg_ids = {}
    for reg_id, _ in pairs(M.def) do
      table.insert(reg_ids, reg_id)
    end
    table.sort(reg_ids)
    buffer.opts.reg_ids = reg_ids
  end

  local reg_values = M.read(reg_ids)

  local show_old_values = buffer.opts.show_old_values
  for i = 1, #reg_ids do
    local line
    local reg_id = reg_ids[i]
    local reg_name = M.name(reg_id)
    local reg_value = reg_values[i]
    local old_reg_value = old_reg_values[i]
    local changed = false

    if old_reg_value and old_reg_value ~= reg_value then
      changed = true
      if show_old_values then
        line = string.format("%-5s = %016x <= %016x", reg_name, reg_value, old_reg_value)
      else
        line = string.format("%-5s = %016x", reg_name, reg_value)
      end
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

  buffer.opts.old_reg_values = reg_values

  buffer.update(lines, highlight)
end

return M

