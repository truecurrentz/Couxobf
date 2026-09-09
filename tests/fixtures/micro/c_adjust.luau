local function f(a,b,c) return a,b,c end
print(f(1))
print(f(1,2,3,4))
local function h() return 1,2 end
print(f(h()))
print(f(0,h()))
