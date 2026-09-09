local t={a=1,b=2,c=3} local n=0
for k,v in next,t do n+=1 end
print(n)
local u={} for k in next,u,nil do n+=100 end print(n)
