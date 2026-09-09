local function f() return 1,2,3 end
local a,b,c = f()
print(a,b,c)
local x = f()
print(x)
print(f(), 9)
local t = {f()}
print(#t, t[1], t[3])
