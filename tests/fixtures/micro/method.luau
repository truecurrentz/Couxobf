local o={v=10} function o:get(x) return self.v+x end
print(o:get(5))
local m=o.get print(m(o,1))
