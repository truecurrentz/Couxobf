-- Operator metamethods: a value type whose arithmetic, comparison and
-- printing all route through a metatable, plus a container that uses them.
local Vec = {}
Vec.__index = Vec

function Vec.new(x, y)
	return setmetatable({ x = x, y = y }, Vec)
end

function Vec.__add(a, b)
	return Vec.new(a.x + b.x, a.y + b.y)
end

function Vec.__sub(a, b)
	return Vec.new(a.x - b.x, a.y - b.y)
end

function Vec.__mul(a, b)
	if type(b) == "number" then
		return Vec.new(a.x * b, a.y * b)
	end
	return a.x * b.x + a.y * b.y
end

function Vec.__div(a, k)
	return Vec.new(a.x / k, a.y / k)
end

function Vec.__unm(a)
	return Vec.new(-a.x, -a.y)
end

function Vec.__eq(a, b)
	return a.x == b.x and a.y == b.y
end

function Vec.__lt(a, b)
	return a.x * a.x + a.y * a.y < b.x * b.x + b.y * b.y
end

function Vec.__tostring(v)
	return string.format("(%g,%g)", v.x, v.y)
end

function Vec:length()
	return (self.x * self.x + self.y * self.y) ^ 0.5
end

function Vec:normalized()
	local len = self:length()
	if len == 0 then
		return Vec.new(0, 0)
	end
	return self / len
end

local a = Vec.new(3, 4)
local b = Vec.new(1, -2)
print(tostring(a + b), tostring(a - b), tostring(a * 2), tostring(a * b))
print(tostring(-a), a:length(), tostring(a:normalized()))
print(a == Vec.new(3, 4), a < b, b < a)
print(tostring(a / 2), (a / 2).x, (a / 2).y)

local function sum_vectors(list)
	local acc = Vec.new(0, 0)
	for _, v in ipairs(list) do
		acc = acc + v
	end
	return acc, acc:length()
end

print(sum_vectors({ Vec.new(1, 0), Vec.new(0, 1), Vec.new(-1, -1) }))

local function scale_all(list, k)
	local out = {}
	for i, v in ipairs(list) do
		out[i] = v * k
	end
	return out
end

local scaled = scale_all({ Vec.new(1, 2), Vec.new(3, 4) }, 10)
print(tostring(scaled[1]), tostring(scaled[2]))
