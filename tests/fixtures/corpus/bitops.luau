-- Integer-flavoured helpers: base conversion, hashing, checksums and the
-- bit-twiddling a protocol implementation tends to grow.
local function to_base(n, base)
	local digits = "0123456789abcdef"
	local out = {}
	local i = 0
	if n == 0 then
		return "0"
	end
	while n > 0 do
		i += 1
		out[i] = string.sub(digits, (n % base) + 1, (n % base) + 1)
		n = n // base
	end
	local reversed = {}
	for j = 1, i do
		reversed[j] = out[i - j + 1]
	end
	return table.concat(reversed)
end

local function from_base(text, base)
	local digits = "0123456789abcdef"
	local acc = 0
	for i = 1, #text do
		local value = string.find(digits, string.sub(text, i, i), 1, true)
		if value == nil then
			return nil
		end
		acc = acc * base + (value - 1)
	end
	return acc
end

local function fnv1a(s)
	local hash = 2166136261
	for i = 1, #s do
		hash = bit32.bxor(hash, string.byte(s, i)) % 4294967296
		hash = (hash * 16777619) % 4294967296
	end
	return hash
end

local function popcount(v)
	local n = 0
	while v > 0 do
		n += v % 2
		v = v // 2
	end
	return n
end

local function rotate_left(v, bits, width)
	local mask = 2 ^ width - 1
	v = v % (mask + 1)
	local shifted = (v * 2 ^ bits) % (mask + 1)
	local carried = v // (2 ^ (width - bits))
	return (shifted + carried) % (mask + 1)
end

local function xor_bytes(a, b)
	local out = {}
	for i = 1, #a do
		out[i] = string.char(bit32.bxor(string.byte(a, i), string.byte(b, i)))
	end
	return table.concat(out)
end

local function checksum8(s)
	local acc = 0
	for i = 1, #s do
		acc = (acc + string.byte(s, i) * (i % 7 + 1)) % 256
	end
	return acc
end

local function run_length_encode(s)
	local out = {}
	local last = nil
	local count = 0
	for i = 1, #s do
		local ch = string.sub(s, i, i)
		if ch == last then
			count += 1
		else
			if last ~= nil then
				out[#out + 1] = last .. count
			end
			last = ch
			count = 1
		end
	end
	if last ~= nil then
		out[#out + 1] = last .. count
	end
	return table.concat(out)
end

print(to_base(255, 16), to_base(10, 2), to_base(0, 8))
print(from_base("ff", 16), from_base("1010", 2), from_base("zz", 16))
print(fnv1a("couxobf"), fnv1a(""))
print(popcount(255), popcount(256), popcount(0))
print(rotate_left(1, 1, 8), rotate_left(128, 1, 8), rotate_left(0b1011, 2, 4))
print(#xor_bytes("\1\2\3", "\3\2\1"), checksum8("hello"))
print(run_length_encode("aaaabcca"))
