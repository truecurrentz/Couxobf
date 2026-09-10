-- Error handling: pcall / xpcall, error objects, and the exact messages a
-- protected build has to reproduce.
local function risky(kind)
	if kind == "text" then
		error("plain failure", 0)
	elseif kind == "table" then
		error({ code = 7, retry = true }, 0)
	elseif kind == "nil" then
		error(nil, 0)
	else
		return "ok", kind
	end
end

for _, kind in ipairs({ "text", "table", "nil", "fine" }) do
	local ok, err = pcall(risky, kind)
	print(kind, ok, type(err))
	if type(err) == "table" then
		print(err.code, err.retry)
	elseif type(err) == "string" then
		print(err)
	end
end

local function traced(fn, ...)
	return xpcall(fn, function(message)
		return "wrapped: " .. tostring(message)
	end, ...)
end

print(traced(function()
	return 1 + 1
end))
print(traced(function()
	error("boom", 0)
end))

local function retry(times, fn)
	local last = nil
	for i = 1, times do
		local ok, err = pcall(fn, i)
		if ok then
			return "ok", i, err
		end
		last = err
	end
	return "failed", times, last
end

local attempts = 0
print(retry(4, function(i)
	attempts += 1
	if attempts < 3 then
		error("not yet", 0)
	end
	return "done-" .. i
end))

local function assert_args(x, y)
	-- `assert` with a level-2 message would prefix the failing file and line,
	-- which a protected build cannot reproduce; the guards are raised without
	-- position information so the two sides print the same text.
	if type(x) ~= "number" then
		error("x must be a number", 0)
	end
	if y == 0 then
		error("y must not be zero", 0)
	end
	return x / y
end

print(pcall(assert_args, 10, 2))
print(pcall(assert_args, "10", 2))
print(pcall(assert_args, 10, 0))
