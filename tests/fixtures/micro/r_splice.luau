local t = {7, 8}
local function f(n)
  if n > 0 then
    return n, table.unpack(t)
  end
end
print(f(1))
local function g() return 1, table.unpack(t) end
print(g())
local function h(a) return a, table.unpack(t) end
print(h(0))
