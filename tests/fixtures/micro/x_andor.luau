local function t() return 1 end
print(false or 5, nil or "d", 1 and 2, nil and 2)
print(t() and 9)
local x = nil print(x or x or 3)
