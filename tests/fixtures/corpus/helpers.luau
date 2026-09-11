-- Nested helpers: the closure shapes that capture *nothing*.  A comparator
-- handed to `table.sort`, a helper beside the loop that calls it, a callback
-- stored in a table, three levels of nesting, a helper that outlives the call
-- that built it.  `closures.luau` is the other half of the pair: every closure
-- there captures, which is the case a VM frame cannot serve.
local function squared_sum(xs)
	local function square(x)
		return x * x
	end
	local total = 0
	for i = 1, #xs do
		total += square(xs[i])
	end
	return total
end

print(squared_sum({ 1, 2, 3, 4 }))
print(squared_sum({}))
print(squared_sum({ -5, 5, 12 }))

local function by_length(words)
	local function shorter(a, b)
		if #a ~= #b then
			return #a < #b
		end
		return a < b
	end
	table.sort(words, shorter)
	return table.concat(words, ",")
end

print(by_length({ "pear", "fig", "apple", "kiwi" }))
print(by_length({ "a", "ab", "abc" }))

local function pipeline(values)
	local function double(x)
		return x * 2
	end
	local function inc(x)
		return x + 1
	end
	local out = {}
	for i = 1, #values do
		local function tag(v)
			return "<" .. v .. ">"
		end
		out[i] = tag(inc(double(values[i])))
	end
	return table.concat(out, " ")
end

print(pipeline({ 1, 2, 3 }))
print(pipeline({ 10, -4 }))

local function outer(n)
	local function middle(x)
		local function inner(y)
			return y * 3
		end
		return inner(x) + 1
	end
	local acc = 0
	for i = 1, n do
		acc += middle(i)
	end
	return acc
end

print(outer(4), outer(1), outer(9))

local handlers = {}
local function register(name)
	local function handle(x)
		return "v" .. tostring(x * 7)
	end
	handlers[name] = handle
	return handle
end

print(register("a")(2), register("b")(3))
print(handlers["a"](4), handlers["b"](5))

local function make_adder()
	local function add(a, b)
		return a + b
	end
	return add
end

local adder = make_adder()
print(adder(2, 3), adder(adder(1, 1), 10))

local function retry(times, value)
	local function attempt(v)
		return v % 5
	end
	local last = 0
	for i = 1, times do
		last = attempt(value + i)
	end
	return last
end

print(retry(3, 9), retry(7, 14), retry(1, 0))
