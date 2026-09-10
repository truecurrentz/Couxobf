-- Table construction, indexing and method-style calls through plain tables.
local function histogram(words)
	local counts = {}
	for i = 1, #words do
		local w = words[i]
		if counts[w] == nil then
			counts[w] = 1
		else
			counts[w] += 1
		end
	end
	return counts
end

local function top(counts)
	local best, key = -1, ""
	for k, v in pairs(counts) do
		if v > best or (v == best and k < key) then
			best, key = v, k
		end
	end
	return key, best
end

local h = histogram({ "ash", "bee", "ash", "cat", "bee", "ash" })
local k, n = top(h)
print(k, n, h.bee, h.dog == nil)

local grid = {}
for r = 1, 4 do
	grid[r] = {}
	for c = 1, 4 do
		grid[r][c] = r * 10 + c
	end
end
print(grid[3][4] + grid[1][1] + #grid)
