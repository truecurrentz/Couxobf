-- Closures: counters, per-iteration capture, higher-order combinators and a
-- memoizer -- the shapes that decide whether a callback-heavy program can run
-- inside the VM at all.
local function make_counter(start)
	local n = start
	return function(step)
		n += step or 1
		return n
	end
end

local counter = make_counter(10)
print(counter(), counter(5), counter(-2))

local function per_iteration()
	local fns = {}
	for i = 1, 3 do
		fns[i] = function()
			return i * i
		end
	end
	local out = {}
	for i, fn in ipairs(fns) do
		out[i] = fn()
	end
	return table.concat(out, ",")
end

print(per_iteration())

local function compose(f, g)
	return function(x)
		return f(g(x))
	end
end

local double = function(x)
	return x * 2
end
local inc = function(x)
	return x + 1
end
print(compose(double, inc)(5))

local function memoize(fn)
	local cache = {}
	return function(k)
		local hit = cache[k]
		if hit ~= nil then
			return hit
		end
		local v = fn(k)
		cache[k] = v
		return v
	end
end

local calls = 0
local slow = memoize(function(n)
	calls += 1
	local acc = 0
	for i = 1, n do
		acc += i
	end
	return acc
end)

print(slow(4), slow(4), slow(7), calls)

local function adder_chain(n)
	local acc = 0
	local function add(x)
		acc += x
		return acc
	end
	for i = 1, n do
		add(i)
	end
	return add(0), acc
end

print(adder_chain(10))
