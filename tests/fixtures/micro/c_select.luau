local function f(...) return select("#",...), select(2,...) end
print(f(1,2,3))
local function g(n,...) return select(n,...) end
print(g(2,7,8,9))
