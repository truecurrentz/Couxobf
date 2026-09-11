-- String helpers: slicing, padding, splitting, simple patterns and building.
-- Deliberately library-light so the functions themselves are what gets
-- virtualized rather than the calls into `string`.
local function pad_left(s, width, fill)
	fill = fill or " "
	local out = s
	while #out < width do
		out = fill .. out
	end
	return out
end

local function pad_right(s, width, fill)
	fill = fill or " "
	local out = s
	while #out < width do
		out = out .. fill
	end
	return out
end

local function split(s, sep)
	local out = {}
	local start = 1
	while true do
		local at = string.find(s, sep, start, true)
		if at == nil then
			out[#out + 1] = string.sub(s, start)
			break
		end
		out[#out + 1] = string.sub(s, start, at - 1)
		start = at + #sep
	end
	return out
end

local function title_case(s)
	local out = {}
	local capitalize = true
	for i = 1, #s do
		local ch = string.sub(s, i, i)
		if ch == " " then
			capitalize = true
			out[i] = ch
		elseif capitalize then
			out[i] = string.upper(ch)
			capitalize = false
		else
			out[i] = ch
		end
	end
	return table.concat(out)
end

local function count_words(s)
	local n = 0
	local in_word = false
	for i = 1, #s do
		local ch = string.sub(s, i, i)
		if ch == " " or ch == "\t" or ch == "\n" then
			in_word = false
		elseif not in_word then
			n += 1
			in_word = true
		end
	end
	return n
end

local function reverse(s)
	local out = {}
	local n = #s
	for i = 1, n do
		out[i] = string.sub(s, n - i + 1, n - i + 1)
	end
	return table.concat(out)
end

local function wrap(text, width)
	local lines = {}
	local current = ""
	for word in string.gmatch(text, "%S+") do
		if #current == 0 then
			current = word
		elseif #current + 1 + #word <= width then
			current = current .. " " .. word
		else
			lines[#lines + 1] = current
			current = word
		end
	end
	if #current > 0 then
		lines[#lines + 1] = current
	end
	return lines
end

print("[" .. pad_left("7", 4, "0") .. "]")
print("[" .. pad_right("hi", 5, ".") .. "]")
print(table.concat(split("a,b,,c", ","), "|"), #split("a,b,,c", ","))
print(title_case("hello there world"))
print(count_words(" one  two\nthree\tfour "))
print(reverse("couxobf"))
print(table.concat(wrap("the quick brown fox jumps over the lazy dog", 12), "/"))
