local function sum(...) local t={...} local s=0 for i=1,#t do s+=t[i] end return s end
print(sum(1,2,3,4,5))
local function f() return 10,20 end
print((f()))
local a=(f()) print(a)
