-- A state machine over a token stream: many blocks, mixed terminators.
local function scan(tokens)
	local state = 0
	local value = 0
	local i = 1
	while i <= #tokens do
		local t = tokens[i]
		if state == 0 then
			if t == "num" then
				state = 1
			elseif t == "op" then
				state = 2
			else
				state = 3
			end
		elseif state == 1 then
			value += i
			if t == "op" then
				state = 2
			else
				state = 0
			end
		elseif state == 2 then
			value *= 2
			state = 0
		else
			value -= 1
			if t == "end" then
				break
			end
			state = 0
		end
		i += 1
	end
	return value, state
end

local seq = { "num", "num", "op", "num", "skip", "op", "end", "num" }
print(scan(seq))
print(scan({ "op", "op", "num" }))
print(scan({}))

local function pick(i)
	for k = 1, 3 do
		if i == k then
			return k * 10
		end
	end
	return -1
end
print(pick(2), pick(5))
