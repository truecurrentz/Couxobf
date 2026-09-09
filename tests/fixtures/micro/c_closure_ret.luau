local function mk(n) return function() return n end end
print(mk(5)(), mk(6)())
local t={mk(1),mk(2)} print(t[1](), t[2]())
