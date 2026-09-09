local function e() error({code=42}) end
local ok,v = pcall(e) print(ok, type(v), v and v.code)
print(pcall(function() return 1,2 end))
local ok2,r1,r2 = pcall(function() return 1,2 end) print(ok2,r1,r2)
