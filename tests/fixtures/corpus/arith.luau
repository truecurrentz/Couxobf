-- Arithmetic and comparison coverage: every binary operator the VM has a
-- handler for, plus `>=` / `~=` in loop and branch position.
local function divide(a, b)
	local q = a / b
	local f = a // b
	local r = a % b
	return q, f, r
end

print(divide(17, 5))
print(divide(-17, 5))
print(divide(17.5, 2.5))

local function powers(n)
	local acc = 1
	for i = 1, 4 do
		acc = acc * (n ^ (i % 3))
	end
	return acc, -acc, #tostring(acc)
end

print(powers(2))
print(powers(0.5))

local function classify(x, y)
	if x >= y then
		if x ~= y then
			return "gt"
		end
		return "eq"
	end
	if x + 1 <= y then
		return "le1"
	end
	return "lt"
end

print(classify(3, 3), classify(4, 3), classify(2, 3), classify(2, 4))

local function gcd(a, b)
	while b ~= 0 do
		a, b = b, a % b
	end
	return a
end

print(gcd(462, 1071), gcd(9, 3))
