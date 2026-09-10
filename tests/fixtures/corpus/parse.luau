-- A tiny expression tokenizer and evaluator: character classification,
-- dispatch on a token kind, and a recursive-descent parser over the result.
local DIGITS = "0123456789"

local function is_digit(ch)
	return string.find(DIGITS, ch, 1, true) ~= nil
end

local function is_space(ch)
	return ch == " " or ch == "\t" or ch == "\n"
end

local function is_operator(ch)
	return ch == "+" or ch == "-" or ch == "*" or ch == "/"
end

local function tokenize(src)
	local tokens = {}
	local i = 1
	while i <= #src do
		local ch = string.sub(src, i, i)
		if is_space(ch) then
			i += 1
		elseif is_digit(ch) then
			local start = i
			while i <= #src and is_digit(string.sub(src, i, i)) do
				i += 1
			end
			tokens[#tokens + 1] = { kind = "num", text = string.sub(src, start, i - 1) }
		elseif is_operator(ch) then
			tokens[#tokens + 1] = { kind = "op", text = ch }
			i += 1
		elseif ch == "(" or ch == ")" then
			tokens[#tokens + 1] = { kind = "paren", text = ch }
			i += 1
		else
			tokens[#tokens + 1] = { kind = "unknown", text = ch }
			i += 1
		end
	end
	return tokens
end

local function render(tokens)
	local out = {}
	for i, tok in ipairs(tokens) do
		out[i] = tok.kind .. ":" .. tok.text
	end
	return table.concat(out, " ")
end

local Parser = {}
Parser.__index = Parser

function Parser.new(tokens)
	return setmetatable({ tokens = tokens, pos = 1 }, Parser)
end

function Parser:peek()
	return self.tokens[self.pos]
end

function Parser:next()
	local tok = self.tokens[self.pos]
	self.pos += 1
	return tok
end

function Parser:parse_primary()
	local tok = self:next()
	if tok == nil then
		error("unexpected end of input", 0)
	end
	if tok.kind == "num" then
		return tonumber(tok.text)
	end
	if tok.kind == "paren" and tok.text == "(" then
		local value = self:parse_expr()
		local close = self:next()
		if close == nil or close.text ~= ")" then
			error("expected ')'", 0)
		end
		return value
	end
	if tok.kind == "op" and (tok.text == "-" or tok.text == "+") then
		local value = self:parse_primary()
		return tok.text == "-" and -value or value
	end
	error("unexpected token " .. tostring(tok.text), 0)
end

function Parser:parse_term()
	local value = self:parse_primary()
	while true do
		local tok = self:peek()
		if tok == nil or tok.kind ~= "op" then
			break
		end
		if tok.text ~= "*" and tok.text ~= "/" then
			break
		end
		self:next()
		local rhs = self:parse_primary()
		value = tok.text == "*" and value * rhs or value / rhs
	end
	return value
end

function Parser:parse_expr()
	local value = self:parse_term()
	while true do
		local tok = self:peek()
		if tok == nil or tok.kind ~= "op" then
			break
		end
		if tok.text ~= "+" and tok.text ~= "-" then
			break
		end
		self:next()
		local rhs = self:parse_term()
		value = tok.text == "+" and value + rhs or value - rhs
	end
	return value
end

local function evaluate(src)
	local ok, result = pcall(function()
		return Parser.new(tokenize(src)):parse_expr()
	end)
	if ok then
		return result
	end
	return "error: " .. tostring(result)
end

local toks = tokenize("12 + (3 * 4) - 5 / 2")
print(render(toks))
print(evaluate("12 + (3 * 4) - 5 / 2"))
print(evaluate("2 * (3 + 4) / 7"))
print(evaluate("-8 + 3"))
print(evaluate("1 +"))
print(evaluate("4 $ 2"))
