do
  local a
  for a,b in pairs{} do error("not here") end
  for i=1,0 do error("not here") end
  for i=0,1,-1 do error("not here") end
  a = nil; for i=1,1 do assert(not a); a=1 end; assert(a)
  a = nil; for i=1,1,-1 do assert(not a); a=1 end; assert(a)
  a = 0; for i=0, 1, 0.1 do a=a+1 end; assert(a==11)
end
print("ok")
