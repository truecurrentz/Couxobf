-- Nested loops with breaks and repeats: many blocks, several terminators.
local function sieve(limit)
	local marks = {}
	for i = 2, limit do
		marks[i] = false
	end
	local count = 0
	for p = 2, limit do
		if not marks[p] then
			count += 1
			local m = p * p
			while m <= limit do
				marks[m] = true
				m += p
			end
		end
	end
	return count
end

local function collatz(n)
	local steps = 0
	repeat
		if n % 2 == 0 then
			n = n // 2
		else
			n = 3 * n + 1
		end
		steps += 1
	until n == 1
	return steps
end

print(sieve(60), collatz(27), collatz(97))
