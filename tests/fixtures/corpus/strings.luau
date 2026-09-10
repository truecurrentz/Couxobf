-- String processing: concat, sub, byte, format, interpolation.
local function runlength(s)
	if #s == 0 then
		return ""
	end
	local out = {}
	local prev = s:sub(1, 1)
	local run = 1
	for i = 2, #s do
		local ch = s:sub(i, i)
		if ch == prev then
			run += 1
		else
			table.insert(out, prev .. run)
			prev, run = ch, 1
		end
	end
	table.insert(out, prev .. run)
	return table.concat(out, ",")
end

local function checksum(s)
	local acc = 0
	for i = 1, #s do
		acc = (acc + string.byte(s, i) * i) % 1000003
	end
	return acc
end

print(runlength("aaabbc"))
print(runlength(""))
print(runlength("xyz"))
print(checksum("couxobf"), checksum(`lit-{1 + 1}`))
local name = "grid"
print(`{name}[{#name}] = {name:rep(2)}`)
