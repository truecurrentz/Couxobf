-- A small data-structure module: closures over shared state, methods and an
-- iterator the caller drives.
local function new_queue()
	local items = {}
	local head = 1
	local tail = 0
	local function push(value)
		tail += 1
		items[tail] = value
		return tail - head + 1
	end
	local function pop()
		if head > tail then
			return nil
		end
		local value = items[head]
		items[head] = nil
		head += 1
		return value
	end
	local function size()
		return tail - head + 1
	end
	local function drain()
		local out = {}
		local n = 0
		while size() > 0 do
			n += 1
			out[n] = pop()
		end
		return out
	end
	return {
		push = push,
		pop = pop,
		size = size,
		drain = drain,
	}
end

local q = new_queue()
print(q.push("a"), q.push("b"), q.push("c"), q.size())
print(q.pop(), q.pop(), q.size())
q.push("d")
print(table.concat(q.drain(), ","), q.size())
print(q.pop())

local function new_stack(limit)
	local depth = 0
	local top = nil
	return {
		push = function(value)
			if depth >= limit then
				return false, "full"
			end
			depth += 1
			top = { value = value, below = top }
			return true, depth
		end,
		pop = function()
			if top == nil then
				return nil
			end
			local value = top.value
			top = top.below
			depth -= 1
			return value
		end,
		depth = function()
			return depth
		end,
	}
end

local s = new_stack(3)
print(s.push(1))
print(s.push(2))
print(s.push(3))
print(s.push(4))
print(s.pop(), s.pop(), s.depth())
print(s.pop(), s.pop(), s.depth())

local function map_over(list, fn)
	local out = {}
	for i = 1, #list do
		out[i] = fn(list[i], i)
	end
	return out
end

local doubled = map_over({ 1, 2, 3, 4 }, function(v, i)
	return v * i
end)
print(table.concat(doubled, ","))
