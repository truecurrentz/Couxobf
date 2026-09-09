local f = if 1<2 then "y" else "n" print(f)
local g = function(n) return if n>0 then 1 elseif n<0 then -1 else 0 end
print(g(5), g(-5), g(0))
