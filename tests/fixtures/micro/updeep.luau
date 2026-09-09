local v=1
local function a() local function b() local function c() return v end return c end return b end
print(a()()())
v=2 print(a()()())
