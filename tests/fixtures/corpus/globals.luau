-- Global reads and writes from inside functions: the scaffolding has to keep
-- the program's own globals live and observable from outside the function
-- that set them.
Counter = 0
Log = {}

local function bump(by)
	Counter = Counter + by
	return Counter
end

print(bump(3), bump(7), Counter)

local function record(tag, value)
	Log[#Log + 1] = tag .. "=" .. tostring(value)
	Counter = #Log
	return true
end

print(record("a", 1), record("b", "two"), Counter)
print(table.concat(Log, ";"))

local function reset()
	Counter = 0
	Log = {}
	return Counter, #Log
end

print(reset())

local function install(name, fn)
	_G = _G or {}
	Log[name] = fn
	return fn(4)
end

print(install("square", function(x)
	return x * x
end))
print(type(Log.square), Counter)
