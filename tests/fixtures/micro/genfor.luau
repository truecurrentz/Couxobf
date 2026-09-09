local t={a=1,b=2} local s=0 for k,v in pairs(t) do s+=v end print(s)
local u={10,20} local q=0 for _,v in ipairs(u) do q+=v end print(q)
local function it(n) local i=0 return function() i+=1 if i<=n then return i end end end
local z=0 for v in it(4) do z+=v end print(z)
