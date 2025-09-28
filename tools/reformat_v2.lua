local path=arg[1]; if not path then error("Usage: luajit reformat_v2.lua <file>") end
local f=assert(io.open(path,"rb")); local code=f:read("*a"); f:close()
code=code:gsub("\r\n","\n"):gsub("%s+\n","\n")
local out,indent,pad={},0,"  "
for line in code:gmatch("[^\n]*\n?") do
  if line == "" then break end
  local trimmed=line:gsub("^%s+","")
  if trimmed:match("^end") or trimmed:match("^else") then indent=math.max(0,indent-1) end
  table.insert(out,(pad):rep(indent)..trimmed)
  if trimmed:match("do$") or trimmed:match("then$") or trimmed:match("^function") then indent=indent+1 end
end
print("-- Reformatted\n"..table.concat(out))
