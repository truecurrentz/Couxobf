local function it(s,c) local k=next(s,c) if k then return k,s[k] end end
local t={x=1} for k,v in it,t do print(k,v) end
