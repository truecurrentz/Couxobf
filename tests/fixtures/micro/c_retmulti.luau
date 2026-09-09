local function f() return 1,2,3 end
local function g() return f() end
print(g())
local function h() return 0, f() end
print(h())
local function k(...) return ... end
print(k(f()))
