local function a(x) return x+1 end
local function b(x) return a(a(x)) end
print(b(1))
local t={f=function(self,x) return x*2 end} print(t:f(21))
