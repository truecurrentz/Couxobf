local fs={}
for i=1,3 do fs[i]=function() return i end end
print(fs[1](),fs[2](),fs[3]())
