-- Numeric kernels: integer and float paths, comparisons, unary ops.
local function dot(a, b)
	local s = 0
	for i = 1, #a do
		s += a[i] * b[i]
	end
	return s
end

local function norm(v)
	local s = 0
	for i = 1, #v do
		s += v[i] ^ 2
	end
	return s ^ 0.5
end

local function clamp(x, lo, hi)
	if x < lo then
		return lo
	elseif x > hi then
		return hi
	end
	return x
end

local function lerp(a, b, t)
	return a + (b - a) * t
end

local v1 = { 1, 2, 3, 4 }
local v2 = { 4, -3, 2, -1 }
print(dot(v1, v2))
print(string.format("%.3f", norm({ 3, 4 })))
print(clamp(-5, 0, 10), clamp(15, 0, 10), clamp(5, 0, 10))
print(string.format("%.2f", lerp(10, 20, 0.25)))
print(-3.5 % 2, 7 // 2, 7 / 2, #"abc")
