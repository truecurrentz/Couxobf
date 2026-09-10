-- An application-shaped program: methods, a metatable, string building and
-- a report pass -- the mixture a real script hands the obfuscator.
local Inventory = {}
Inventory.__index = Inventory

function Inventory.new(name)
	local self = setmetatable({}, Inventory)
	self.name = name
	self.rows = {}
	return self
end

function Inventory:add(sku, label, unit_price, stock)
	self.rows[sku] = {
		label = label,
		unit_price = unit_price,
		stock = stock,
	}
end

function Inventory:discount_for(quantity)
	if quantity >= 100 then
		return 0.25
	elseif quantity >= 25 then
		return 0.1
	elseif quantity >= 5 then
		return 0.05
	end
	return 0
end

function Inventory:total_for(sku, quantity)
	local row = self.rows[sku]
	if row == nil then
		return nil, "unknown sku"
	end
	if row.stock < quantity then
		return nil, "insufficient stock"
	end
	local rate = self:discount_for(quantity)
	local gross = row.unit_price * quantity
	return gross - gross * rate
end

function Inventory:report()
	local lines = {}
	local total = 0
	local index = 0
	for sku, row in pairs(self.rows) do
		index += 1
		lines[index] = string.format("%s %s %d @ %.2f", sku, row.label, row.stock, row.unit_price)
		total += row.unit_price * row.stock
	end
	table.sort(lines)
	return table.concat(lines, "\n"), string.format("%.2f", total)
end

local shop = Inventory.new("main")
shop:add("A-1", "Widget", 3.5, 40)
shop:add("B-2", "Gadget", 12.25, 8)
shop:add("C-3", "Doohickey", 0.99, 250)

print(shop:total_for("A-1", 10))
print(shop:total_for("A-1", 30))
print(shop:total_for("B-2", 100))
print(shop:total_for("Z-9", 1))
print(shop:report())
print(getmetatable(shop) == Inventory, shop.name)

function Inventory:restock(sku, amount)
	local row = self.rows[sku]
	if row == nil then
		return false
	end
	row.stock += amount
	return true, row.stock
end

print(shop:restock("B-2", 12))
print(shop:restock("nope", 1))
