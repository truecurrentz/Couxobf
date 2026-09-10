-- Descriptive statistics over plain tables: enough small numeric functions
-- that a build's virtualization decisions are spread across the file.
local function mean(xs)
	local total = 0
	for i = 1, #xs do
		total += xs[i]
	end
	if #xs == 0 then
		return 0
	end
	return total / #xs
end

local function variance(xs)
	local m = mean(xs)
	local acc = 0
	for i = 1, #xs do
		local d = xs[i] - m
		acc += d * d
	end
	if #xs < 2 then
		return 0
	end
	return acc / (#xs - 1)
end

local function median(xs)
	local copy = {}
	for i = 1, #xs do
		copy[i] = xs[i]
	end
	table.sort(copy)
	local n = #copy
	if n == 0 then
		return 0
	end
	if n % 2 == 1 then
		return copy[(n + 1) // 2]
	end
	return (copy[n // 2] + copy[n // 2 + 1]) / 2
end

local function histogram(xs, buckets)
	local lo, hi = xs[1], xs[1]
	for i = 2, #xs do
		if xs[i] < lo then
			lo = xs[i]
		end
		if xs[i] > hi then
			hi = xs[i]
		end
	end
	local width = (hi - lo) / buckets
	local counts = {}
	for i = 1, buckets do
		counts[i] = 0
	end
	for i = 1, #xs do
		local slot = math.floor((xs[i] - lo) / width) + 1
		if slot > buckets then
			slot = buckets
		end
		counts[slot] += 1
	end
	return counts
end

local function z_scores(xs)
	local m = mean(xs)
	local sd = math.sqrt(variance(xs))
	local out = {}
	for i = 1, #xs do
		if sd == 0 then
			out[i] = 0
		else
			out[i] = (xs[i] - m) / sd
		end
	end
	return out
end

local function moving_average(xs, window)
	local out = {}
	for i = 1, #xs do
		local total = 0
		local n = 0
		for j = math.max(1, i - window + 1), i do
			total += xs[j]
			n += 1
		end
		out[i] = total / n
	end
	return out
end

local data = { 4, 8, 15, 16, 23, 42, 4, 9 }
print(string.format("%.4f", mean(data)))
print(string.format("%.4f", variance(data)))
print(median(data), median({ 1, 2, 3, 4 }))
print(table.concat(histogram(data, 4), ","))
local zs = z_scores(data)
print(string.format("%.3f %.3f %.3f", zs[1], zs[4], zs[8]))
local ma = moving_average(data, 3)
print(string.format("%.2f %.2f %.2f", ma[1], ma[3], ma[8]))
