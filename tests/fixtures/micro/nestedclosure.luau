local function mk()
 local c=0
 local function inc() c+=1 return c end
 return inc, function() return c end
end
local i,g = mk() i() i() print(i(), g())
