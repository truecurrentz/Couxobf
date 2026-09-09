local function f(n) if n==0 then return "z" end return f(n-1) end
print(f(5))
local function g(...) return select("#",...) end
print(g(1,2,3))
