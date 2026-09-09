local t={1,2,3} table.insert(t,1,9) print(t[1],t[2],#t)
table.remove(t,1) print(t[1],#t)
print(table.concat({1,2,3},"-"))
local s={3,1,2} table.sort(s) print(s[1],s[2],s[3])
