-- Deep branch ladder: exercises many conditional blocks in one prototype.
local function classify(n)
	local tag = 0
	if n < 0 then
		tag = 1
	elseif n % 7 == 0 then
		tag = 2
	elseif n % 5 == 0 then
		tag = 3
	elseif n % 3 == 0 then
		tag = 4
	elseif n < 10 then
		tag = 5
	elseif n < 100 then
		tag = 6
	elseif n < 1000 then
		tag = 7
	else
		tag = 8
	end
	if tag % 2 == 0 then
		tag += 10
	end
	if tag > 12 then
		tag -= 1
	else
		tag *= 2
	end
	return tag
end

local total = 0
for i = -3, 40 do
	total += classify(i)
end
print(total)
