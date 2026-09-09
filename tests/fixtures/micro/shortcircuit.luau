local n=0 local function f() n+=1 return false end
print(f() and f(), n)
local m=0 local function g() m+=1 return true end
print(g() or g(), m)
