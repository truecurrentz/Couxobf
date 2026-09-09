local function range(n) local i=0 return function() i+=1 if i<=n then return i,i*2 end end end
for a,b in range(3) do print(a,b) end
