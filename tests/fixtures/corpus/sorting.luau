-- Sorting with comparators, string ordering and mixed comparison operators.
local function by_score_then_name(a, b)
	if a.score ~= b.score then
		return a.score > b.score
	end
	return a.name < b.name
end

local function leaderboard(players)
	local copy = {}
	for i, p in ipairs(players) do
		copy[i] = { name = p.name, score = p.score }
	end
	table.sort(copy, by_score_then_name)
	local out = {}
	for i, p in ipairs(copy) do
		out[i] = p.name .. ":" .. p.score
	end
	return table.concat(out, " ")
end

print(leaderboard({
	{ name = "ada", score = 10 },
	{ name = "bob", score = 30 },
	{ name = "cy", score = 30 },
	{ name = "dee", score = 5 },
}))

local function bucket(words)
	local short, long = {}, {}
	for _, w in ipairs(words) do
		if #w >= 5 then
			table.insert(long, w)
		else
			table.insert(short, w)
		end
	end
	table.sort(short)
	table.sort(long)
	return table.concat(short, ",") .. "|" .. table.concat(long, ",")
end

print(bucket({ "pear", "apple", "fig", "banana", "kiwi", "orange" }))

local function insertion_sorted(xs)
	local out = { xs[1] }
	for i = 2, #xs do
		local v = xs[i]
		local j = #out + 1
		while j > 1 and out[j - 1] > v do
			j -= 1
		end
		table.insert(out, j, v)
	end
	return out
end

local sorted = insertion_sorted({ 5, 1, 4, 2, 8, 0, -3, 7 })
print(table.concat(sorted, " "))
