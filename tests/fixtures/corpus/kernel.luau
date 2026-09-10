-- A pile of small numeric kernels.  Each one is big enough to be worth
-- virtualizing and independent of the others, which is what makes the
-- "something actually got virtualized" floor a real measurement rather than
-- a count of one large function's blocks.
local function lerp(a, b, t)
	return a + (b - a) * t
end

local function clamp(v, lo, hi)
	if v < lo then
		return lo
	end
	if v > hi then
		return hi
	end
	return v
end

local function smoothstep(edge0, edge1, x)
	local t = clamp((x - edge0) / (edge1 - edge0), 0, 1)
	return t * t * (3 - 2 * t)
end

local function fib(n)
	local a, b = 0, 1
	for _ = 1, n do
		a, b = b, a + b
	end
	return a
end

local function factorial(n)
	local acc = 1
	for i = 2, n do
		acc *= i
	end
	return acc
end

local function is_prime(n)
	if n < 2 then
		return false
	end
	local d = 2
	while d * d <= n do
		if n % d == 0 then
			return false
		end
		d += 1
	end
	return true
end

local function prime_count(limit)
	local found = 0
	for i = 2, limit do
		if is_prime(i) then
			found += 1
		end
	end
	return found
end

local function newton(c, guess)
	local x = guess or 1
	for _ = 1, 8 do
		x = (x + c / x) / 2
	end
	return x
end

local function harmonic(n)
	local acc = 0
	for i = 1, n do
		acc += 1 / i
	end
	return acc
end

local function bit_twiddle(v)
	local acc = 0
	for i = 0, 7 do
		if v % 2 == 1 then
			acc += 2 ^ (7 - i)
		end
		v = v // 2
	end
	return acc
end

print(string.format("%.3f", lerp(0, 10, 0.25)))
print(clamp(-5, 0, 1), clamp(0.5, 0, 1), clamp(9, 0, 1))
print(string.format("%.4f", smoothstep(0, 1, 0.5)))
print(fib(20), factorial(10))
print(prime_count(50), is_prime(97), is_prime(91))
print(string.format("%.6f", newton(2)), string.format("%.6f", newton(144, 5)))
print(string.format("%.5f", harmonic(10)))
print(bit_twiddle(0b10110010), bit_twiddle(1))
