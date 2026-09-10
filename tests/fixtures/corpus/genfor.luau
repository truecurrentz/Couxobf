-- Generic for (pairs / ipairs / next), table constructors and a global the
-- program assigns from inside a function.
Total = 0

local function tally(scores)
	local by_grade = { A = 0, B = 0, C = 0 }
	for name, score in pairs(scores) do
		if score >= 90 then
			by_grade.A += 1
		elseif score >= 75 then
			by_grade.B += 1
		else
			by_grade.C += 1
		end
		Total += score
	end
	return by_grade
end

local grades = tally({ ada = 97, bob = 81, cy = 66, dee = 90 })
print(grades.A, grades.B, grades.C, Total)

local function sum_list(xs)
	local total = 0
	for i, v in ipairs(xs) do
		total += v * i
	end
	return total
end

print(sum_list({ 4, 5, 6, 7 }))

local function invert(t)
	local out = {}
	for k, v in next, t do
		out[v] = k
	end
	return out
end

local flipped = invert({ one = 1, two = 2, three = 3 })
print(flipped[1], flipped[2], flipped[3])

local function constructor_heavy(n)
	local rows = {}
	for i = 1, n do
		rows[i] = { i, i * i, i * i * i, tostring(i), -i, i / 2 }
	end
	local flat = 0
	for _, row in ipairs(rows) do
		flat += row[1] + row[2] + row[6]
	end
	return flat, #rows
end

print(constructor_heavy(5))
