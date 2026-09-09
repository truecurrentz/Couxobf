local function f(...) local a={...} return function() return #a end end
print(f(1,2,3)())
