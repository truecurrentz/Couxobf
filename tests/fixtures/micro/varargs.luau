local function f(...) return select("#", ...), ... end
print(f(1,2,3))
local function g(...) local a,b = ...; return a,b end
print(g(7,8,9))
local function h(...) return {...} end
local t=h(1,2) print(t[1],t[2],#t)
