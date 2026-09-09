-- inventory.luau
-- A small shop system: stock lookup, pricing with tiered discounts,
-- and a summary line. Exercises functions, closures, loops, tables,
-- string formatting and metamethods.

local Catalog = {}
Catalog.__index = Catalog

function Catalog.new(name)
	local self = setmetatable({}, Catalog)
	self.name = name
	self.items = {}
	return self
end

function Catalog:add(sku, label, unitPrice, stock)
	self.items[sku] = {
		label = label,
		unitPrice = unitPrice,
		stock = stock,
	}
end

function Catalog:discountFor(quantity)
	if quantity >= 100 then
		return 0.25
	elseif quantity >= 25 then
		return 0.10
	elseif quantity >= 5 then
		return 0.05
	end
	return 0
end

function Catalog:totalFor(sku, quantity)
	local item = self.items[sku]
	if item == nil then
		return nil, "unknown sku"
	end
	if item.stock < quantity then
		return nil, "insufficient stock"
	end
	local rate = self:discountFor(quantity)
	local gross = item.unitPrice * quantity
	return gross * (1 - rate), rate
end

local function buildCounter(start)
	local count = start
	return function()
		count = count + 1
		return count
	end
end

local shop = Catalog.new("Taytay Hardware")
shop:add("NAIL-3", "3-inch nails", 0.15, 5000)
shop:add("PLANK-8", "8ft plank", 4.75, 240)
shop:add("SCREW-BOX", "Screw box (500)", 12.5, 60)

local receipts = {}
local nextLine = buildCounter(0)

for _, sku in ipairs({ "NAIL-3", "PLANK-8", "SCREW-BOX", "NAIL-3" }) do
	local quantity = ({ 200, 30, 4, 3 })[nextLine()]
	local net, rate = shop:totalFor(sku, quantity)
	if net then
		table.insert(receipts, string.format("%s x%d @ %.2f (-%d%%) = %.2f", sku, quantity, shop.items[sku].unitPrice, rate * 100, net))
	else
		table.insert(receipts, string.format("%s: %s", sku, rate))
	end
end

local grand = 0
for i = 1, #receipts do
	local line = receipts[i]
	print(i .. ". " .. line)
	for token in line:gmatch("= (%d+%.%d+)") do
		grand = grand + tonumber(token)
	end
end

print(string.format("%s: %d lines, total %.2f", shop.name, #receipts, grand))
