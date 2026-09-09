local t={1,2,3} print(#t, -#t, #"ab")
local m=setmetatable({},{__len=function() return 42 end}) print(#m)
