-- Grid algorithms: neighbour enumeration, flood fill, breadth-first search
-- and path reconstruction over a plain table-of-tables map.
local function make_grid(rows, cols, fill)
	local grid = {}
	for r = 1, rows do
		local row = {}
		for c = 1, cols do
			row[c] = fill
		end
		grid[r] = row
	end
	return grid
end

local function in_bounds(grid, r, c)
	return r >= 1 and c >= 1 and r <= #grid and c <= #grid[1]
end

local function neighbours(grid, r, c)
	local out = {}
	local deltas = { { -1, 0 }, { 1, 0 }, { 0, -1 }, { 0, 1 } }
	for i, d in ipairs(deltas) do
		local nr, nc = r + d[1], c + d[2]
		if in_bounds(grid, nr, nc) then
			out[#out + 1] = { nr, nc }
		end
	end
	return out
end

local function flood_fill(grid, r, c, target)
	local start = grid[r][c]
	if start == target then
		return 0
	end
	local queue = { { r, c } }
	local head = 1
	local painted = 0
	while head <= #queue do
		local cell = queue[head]
		head += 1
		local cr, cc = cell[1], cell[2]
		if grid[cr][cc] == start then
			grid[cr][cc] = target
			painted += 1
			for _, nb in ipairs(neighbours(grid, cr, cc)) do
				queue[#queue + 1] = nb
			end
		end
	end
	return painted
end

local function bfs(grid, start, goal)
	local seen = {}
	local queue = { { start[1], start[2], 0 } }
	local head = 1
	while head <= #queue do
		local node = queue[head]
		head += 1
		local r, c, dist = node[1], node[2], node[3]
		if grid[r][c] ~= 1 then
			if r == goal[1] and c == goal[2] then
				return dist
			end
			local key = r * 1000 + c
			if not seen[key] then
				seen[key] = true
				for _, nb in ipairs(neighbours(grid, r, c)) do
					queue[#queue + 1] = { nb[1], nb[2], dist + 1 }
				end
			end
		end
	end
	return -1
end

local function render(grid)
	local lines = {}
	for r = 1, #grid do
		local cells = {}
		for c = 1, #grid[r] do
			cells[c] = tostring(grid[r][c])
		end
		lines[r] = table.concat(cells, "")
	end
	return table.concat(lines, "/")
end

local function blobs(grid)
	local work = {}
	for r = 1, #grid do
		work[r] = {}
		for c = 1, #grid[r] do
			work[r][c] = grid[r][c]
		end
	end
	local count = 0
	for r = 1, #work do
		for c = 1, #work[r] do
			if work[r][c] == 1 then
				count += 1
				flood_fill(work, r, c, count + 1)
			end
		end
	end
	return count, render(work)
end

local map = {
	{ 0, 0, 1, 0 },
	{ 1, 0, 1, 0 },
	{ 0, 0, 0, 0 },
	{ 0, 1, 1, 1 },
}
print(bfs(map, { 1, 1 }, { 4, 1 }))
print(bfs(map, { 1, 3 }, { 4, 4 }))
local count, painted = blobs(map)
print(count, painted)
local empty = make_grid(3, 3, 0)
print(render(empty), flood_fill(empty, 2, 2, 7))
print(#neighbours(map, 1, 1), #neighbours(map, 2, 2), in_bounds(map, 0, 1))
