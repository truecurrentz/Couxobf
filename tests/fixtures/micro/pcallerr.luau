local ok, e = pcall(function() error("boom") end) print(ok, type(e))
print(pcall(error, "x"))
