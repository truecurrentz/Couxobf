local m=setmetatable({},{__add=function(a,b) return "added" end, __index=function(t,k) return k.."!" end})
print(m+1, m.foo)
