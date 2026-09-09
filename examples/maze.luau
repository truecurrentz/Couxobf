-- maze.luau
-- Breadth-first search over a grid, with path reconstruction and a renderer.
-- Exercises nested functions, closures, tables, multi-returns, string building,
-- the length operator, numeric and generic for loops, and short-circuit logic.

local Grid = {}
Grid.__index = Grid

local WALL = "#"
local OPEN = "."

function Grid.new(width, height, seed)
	local self = setmetatable({}, Grid)
	self.width = width
	self.height = height
	self.cells = {}
	local state = seed
	for y = 1, height do
		local row = {}
		for x = 1, width do
			state = (state * 1103515 + 12345) % 2147483648
			local blocked = (state // 65536) % 100 < 28
			if x == 1 or y == 1 or x == width or y == height then
				blocked = true
			end
			row[x] = blocked and WALL or OPEN
		end
		self.cells[y] = row
	end
	self.cells[2][2] = OPEN
	self.cells[height - 1][width - 1] = OPEN
	return self
end

function Grid:passable(x, y)
	if x < 1 or y < 1 or x > self.width or y > self.height then
		return false
	end
	return self.cells[y][x] == OPEN
end

function Grid:neighbours(x, y)
	local out = {}
	local deltas = { { 1, 0 }, { -1, 0 }, { 0, 1 }, { 0, -1 } }
	for i = 1, #deltas do
		local nx, ny = x + deltas[i][1], y + deltas[i][2]
		if self:passable(nx, ny) then
			table.insert(out, { nx, ny })
		end
	end
	return out
end

local function keyOf(x, y)
	return y * 10000 + x
end

function Grid:findPath(sx, sy, gx, gy)
	local queue = { { sx, sy } }
	local head = 1
	local cameFrom = {}
	local seen = { [keyOf(sx, sy)] = true }
	local steps = 0

	while head <= #queue do
		local node = queue[head]
		head = head + 1
		steps = steps + 1
		local cx, cy = node[1], node[2]

		if cx == gx and cy == gy then
			local path = { { cx, cy } }
			local k = keyOf(cx, cy)
			while cameFrom[k] ~= nil do
				local prev = cameFrom[k]
				table.insert(path, 1, prev)
				k = keyOf(prev[1], prev[2])
			end
			return path, steps
		end

		local nearby = self:neighbours(cx, cy)
		for _, next in ipairs(nearby) do
			local nk = keyOf(next[1], next[2])
			if not seen[nk] then
				seen[nk] = true
				cameFrom[nk] = { cx, cy }
				table.insert(queue, next)
			end
		end
	end

	return nil, steps
end

function Grid:render(path)
	local marked = {}
	if path then
		for i = 1, #path do
			marked[keyOf(path[i][1], path[i][2])] = true
		end
	end
	local lines = {}
	for y = 1, self.height do
		local row = {}
		for x = 1, self.width do
			local cell = self.cells[y][x]
			if x == 2 and y == 2 then
				cell = "S"
			elseif x == self.width - 1 and y == self.height - 1 then
				cell = "G"
			elseif marked[keyOf(x, y)] then
				cell = "*"
			end
			row[x] = cell
		end
		table.insert(lines, table.concat(row))
	end
	return table.concat(lines, "\n")
end

local function summarise(label, path, steps)
	if path == nil then
		return string.format("%s: no route after %d expansions", label, steps)
	end
	local length = #path
	local cost = (length - 1) * 1.0
	return string.format("%s: %d cells, cost %.1f, %d expansions", label, length, cost, steps)
end

local maze = Grid.new(15, 9, 20260909)
local path, steps = maze:findPath(2, 2, maze.width - 1, maze.height - 1)

print(maze:render(path))
print(summarise("bfs", path, steps))

local attempts = 0
local reachable = 0
for seed = 1, 6 do
	local other = Grid.new(11, 7, seed * 7919)
	local p2, s2 = other:findPath(2, 2, other.width - 1, other.height - 1)
	attempts = attempts + 1
	if p2 then
		reachable = reachable + 1
	end
end
print(string.format("reachable: %d/%d", reachable, attempts))
