-- A numeric kernel: dense loops over tables of tables, division-heavy, with
-- several small helpers that are the sort of thing a build wants to
-- virtualize.
local function make_matrix(n)
	local m = {}
	for i = 1, n do
		local row = {}
		for j = 1, n do
			row[j] = (i * 7 + j * 13) % 17
		end
		m[i] = row
	end
	return m
end

local function multiply(a, b)
	local n = #a
	local out = {}
	for i = 1, n do
		local row = {}
		for j = 1, n do
			local acc = 0
			for k = 1, n do
				acc += a[i][k] * b[k][j]
			end
			row[j] = acc
		end
		out[i] = row
	end
	return out
end

local function trace(m)
	local acc = 0
	for i = 1, #m do
		acc += m[i][i]
	end
	return acc
end

local function normalize(m)
	local biggest = 0
	for i = 1, #m do
		for j = 1, #m[i] do
			if m[i][j] > biggest then
				biggest = m[i][j]
			end
		end
	end
	if biggest == 0 then
		return m
	end
	for i = 1, #m do
		for j = 1, #m[i] do
			m[i][j] = m[i][j] / biggest
		end
	end
	return m
end

local m = make_matrix(4)
local product = multiply(m, m)
print(trace(product))
local norm = normalize(product)
print(string.format("%.4f %.4f %.4f", norm[1][1], norm[2][3], norm[4][4]))

local function gaussian(n)
	local total = 0
	for k = 1, n do
		total += k
	end
	return total, total / n, total // n, total % n
end

print(gaussian(100))
print(gaussian(7))
