-- Varargs in every position an application actually uses them: spliced into
-- a call, packed, counted, forwarded and returned.
local function join(sep, ...)
	local parts = table.pack(...)
	local out = {}
	for i = 1, parts.n do
		out[i] = tostring(parts[i])
	end
	return table.concat(out, sep), parts.n
end

print(join("-", 1, 2, 3))
print(join("|", "a"))
print(join(",", nil, nil, "z"))

local function forward(...)
	return join("+", ...)
end

print(forward(1, 2, 3, 4))

local function count_and_sum(...)
	local n = select("#", ...)
	local total = 0
	for i = 1, n do
		total += (select(i, ...) or 0)
	end
	return n, total
end

print(count_and_sum(1, 2, 3))
print(count_and_sum())
print(count_and_sum(10))

local function apply(fn, ...)
	local args = { ... }
	local out = {}
	for i = 1, #args do
		out[i] = fn(args[i])
	end
	return table.unpack(out, 1, #out)
end

print(apply(function(x)
	return x * x
end, 2, 3, 4))
