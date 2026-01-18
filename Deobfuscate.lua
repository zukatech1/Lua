-- PROMETHEUS COMPLETE DEOBFUSCATOR v2.0


print("[*] Initializing Enhanced Prometheus Deobfuscator v2.0...")

local root = "./"
package.path = package.path .. ";" .. root .. "src/?.lua"
package.path = package.path .. ";" .. root .. "build/lua/?.lua"
package.path = package.path .. ";" .. root .. "?.lua"

local status, Parser = pcall(require, "prometheus.parser")
if not status then
    print("\n[!] ERROR: Could not find Prometheus source files.")
    print("Search path used: " .. package.path)
    return
end

local Ast      = require("prometheus.ast")
local visitAst = require("prometheus.visitast")
local Unparser = require("prometheus.unparser")
local util     = require("prometheus.util")
local enums    = require("prometheus.enums")

local AstKind = Ast.AstKind

-- ============================================================================
-- UTILITY: Detect and execute function wrappers in sandboxed environment
-- ============================================================================

local function create_safe_sandbox()
    -- Whitelist of safe functions for wrapped code execution
    local safe_env = {
        -- Math & type conversion
        tostring = tostring,
        tonumber = tonumber,
        type = type,
        pairs = pairs,
        ipairs = ipairs,
        next = next,
        select = select,
        error = error,
        assert = assert,
        unpack = unpack,
        rawget = rawget,
        rawset = rawset,
        rawlen = rawlen,
        getmetatable = getmetatable,
        setmetatable = setmetatable,
        math = {
            floor = math.floor,
            ceil = math.ceil,
            min = math.min,
            max = math.max,
            abs = math.abs,
            sqrt = math.sqrt,
            random = math.random,
            fmod = math.fmod,
        },
        string = {
            sub = string.sub,
            len = string.len,
            char = string.char,
            byte = string.byte,
            format = string.format,
            gsub = string.gsub,
            find = string.find,
            match = string.match,
            gmatch = string.gmatch,
            reverse = string.reverse,
            upper = string.upper,
            lower = string.lower,
            rep = string.rep,
        },
        table = {
            insert = table.insert,
            remove = table.remove,
            concat = table.concat,
            sort = table.sort,
        },
        -- Base64/bit operations
        bit = bit or bit32,
    }
    
    return safe_env
end

local function execute_wrapped_code(code)
    print("[WRAPPER] Executing function wrapper...")
    
    -- Check if it looks like a wrapped function
    if not code:match("^%s*return%s*%(%s*function%s*%(") then
        print("  [!] Not a function wrapper, skipping execution")
        return nil
    end
    
    -- Execute the code directly (trusted source)
    -- The wrapper contains everything it needs internally
    local success, result = pcall(loadstring(code))
    
    if success and type(result) == "string" then
        print(string.format("  [+] Successfully executed wrapper! Got %d bytes of code", #result))
        return result
    elseif success and result then
        print(string.format("  [+] Execution returned result of type: %s", type(result)))
        if type(result) == "function" then
            print("  [!] Result is a function, attempting to call it...")
            local success2, result2 = pcall(result)
            if success2 and type(result2) == "string" then
                print(string.format("  [+] Function returned string: %d bytes", #result2))
                return result2
            elseif success2 then
                print(string.format("  [+] Function call succeeded, returned type: %s", type(result2)))
            else
                print(string.format("  [!] Function call failed: %s", tostring(result2)))
            end
        end
        return nil
    else
        print(string.format("  [!] Execution failed: %s", tostring(result)))
        return nil
    end
end

-- ============================================================================
-- EXTRACT WRAPPED FUNCTION BODY FROM AST
-- Handles: return(function(...) body end)(...)
-- ============================================================================

local function extract_wrapper_body_from_ast(ast)
    print("[WRAPPER-AST] Attempting to extract wrapped function body from AST...")
    
    local extracted_ast = nil
    
    -- Look for the wrapper pattern in the AST
    if ast and ast.body and ast.body.statements and #ast.body.statements > 0 then
        local first_stmt = ast.body.statements[1]
        
        -- Check if it's a return statement
        if first_stmt.kind == AstKind.ReturnStatement then
            print("  [+] First statement is a ReturnStatement")
            
            -- ReturnStatement uses 'args' field
            local return_values = first_stmt.args or first_stmt.values
            
            if return_values and #return_values > 0 then
                local return_value = return_values[1]
                
                -- Check if it's a function call
                if return_value.kind == AstKind.FunctionCallExpression then
                    print("  [+] Return value is FunctionCallExpression")
                    
                    -- FunctionCallExpression uses 'base' instead of 'func'
                    local func = return_value.base
                    
                    if not func then
                        print("  [!] Could not find 'base' in FunctionCallExpression")
                        return nil
                    end
                    
                    print(string.format("  [*] Function kind: %s", tostring(func.kind)))
                    
                    -- The function might be wrapped in parentheses, check for ParenthesesExpression
                    local actual_func = func
                    if func.kind == AstKind.ParenthesesExpression then
                        print("  [*] Function is wrapped in parentheses")
                        actual_func = func.expression
                        print(string.format("  [*] Inner expression kind: %s", tostring(actual_func.kind)))
                    end
                    
                    -- Check if the function is a function literal
                    if actual_func and actual_func.kind == AstKind.FunctionLiteralExpression then
                        print("  [+] Function is FunctionLiteralExpression!")
                        
                        -- Extract the function body as a new AST
                        local wrapped_body = actual_func.body
                        
                        if wrapped_body and wrapped_body.statements then
                            print(string.format("  [+] Extracted %d statements from wrapper body", #wrapped_body.statements))
                            
                            -- Create a new AST with the wrapper body as the root
                            extracted_ast = Ast.TopNode(wrapped_body, ast.globalScope)
                            return extracted_ast
                        end
                    else
                        print(string.format("  [!] Function is not FunctionLiteralExpression: %s", tostring(actual_func and actual_func.kind or "nil")))
                    end
                end
            end
        end
    end
    
    print("  [!] Could not extract wrapped body from AST")
    return nil
end

local function unwrap_function_wrapper(code)
    print("[WRAPPER] Checking for function wrappers...")
    
    -- Try to execute the wrapper first
    local decoded = execute_wrapped_code(code)
    
    if decoded and #decoded > 0 then
        print("  [+] Successfully extracted decoded code from wrapper")
        return decoded
    else
        print("  [!] Could not execute wrapper (likely has anti-tamper)")
        return code
    end
end

-- ============================================================================
-- STATIC CONSTANT ARRAY EXTRACTION
-- Decode escape sequences and extract string values without execution
-- ============================================================================

local function decode_escape_sequences(str)
    -- Convert escape sequences like \110 to actual characters
    local result = {}
    local i = 1
    
    while i <= #str do
        if str:sub(i, i) == "\\" and i + 1 <= #str then
            local next_char = str:sub(i + 1, i + 1)
            
            -- Check for octal escapes (\ddd)
            if next_char:match("%d") then
                local octal = str:match("^(%d%d?%d?)", i + 1)
                if octal then
                    local char_code = tonumber(octal, 8) or tonumber(octal)
                    if char_code and char_code <= 255 then
                        table.insert(result, string.char(char_code))
                        i = i + 1 + #octal
                    else
                        table.insert(result, str:sub(i, i))
                        i = i + 1
                    end
                else
                    table.insert(result, str:sub(i, i))
                    i = i + 1
                end
            -- Check for hex escapes (\xhh)
            elseif next_char == "x" and i + 3 <= #str then
                local hex = str:sub(i + 2, i + 3)
                if hex:match("^%x%x$") then
                    table.insert(result, string.char(tonumber(hex, 16)))
                    i = i + 4
                else
                    table.insert(result, str:sub(i, i))
                    i = i + 1
                end
            -- Standard escapes
            elseif next_char == "n" then
                table.insert(result, "\n")
                i = i + 2
            elseif next_char == "t" then
                table.insert(result, "\t")
                i = i + 2
            elseif next_char == "r" then
                table.insert(result, "\r")
                i = i + 2
            elseif next_char == "\\" then
                table.insert(result, "\\")
                i = i + 2
            elseif next_char == '"' then
                table.insert(result, '"')
                i = i + 2
            else
                table.insert(result, str:sub(i, i))
                i = i + 1
            end
        else
            table.insert(result, str:sub(i, i))
            i = i + 1
        end
    end
    
    return table.concat(result)
end

local function extract_constant_arrays(ast)
    print("[CONST-ARRAY] Extracting constant string arrays...")
    
    local arrays = {}
    local count = 0
    
    -- Find all local variable declarations with table literals
    visitAst(ast, function(node, data)
        if node.kind == AstKind.LocalVariable and node.value and node.value.kind == AstKind.TableExpression then
            print(string.format("  [+] Found table assignment to variable '%s'", node.name))
            
            local strings = {}
            local has_strings = false
            
            -- Extract values from the table
            if node.value.fields then
                for idx, field in ipairs(node.value.fields) do
                    -- Handle both TableFieldExpression and TableEntry
                    local field_value = field.value or field
                    
                    if field_value and field_value.kind == AstKind.StringExpression then
                        local decoded = decode_escape_sequences(field_value.value)
                        strings[idx] = decoded
                        has_strings = true
                    elseif field_value and field_value.kind == AstKind.ConstantNode and type(field_value.value) == "string" then
                        strings[idx] = field_value.value
                        has_strings = true
                    end
                end
            end
            
            if has_strings and #strings > 3 then  -- Track arrays with 3+ strings
                print(string.format("    [+] Array '%s' has %d decoded strings", node.name, #strings))
                arrays[node.name] = {
                    strings = strings,
                    variable = node,
                    indices = strings  -- Map for index->string lookup
                }
                count = count + 1
            end
        end
    end)
    
    print(string.format("  [+] Extracted %d constant arrays with %d total strings", count, 
        (function() local t = 0; for _, a in pairs(arrays) do t = t + #a.strings end; return t end)()))
    
    return arrays
end

local function analyze_string_accessors(ast, arrays)
    print("[STRING-ACCESS] Analyzing string accessor functions...")
    
    local accessors = {}
    local accessor_count = 0
    
    -- Look for function definitions that return from arrays
    -- Pattern: local function name(param) return array[param+offset] end
    visitAst(ast, function(node, data)
        if node.kind == AstKind.LocalFunction then
            local func_name = node.name
            local body = node.body
            
            -- Check function body for array access patterns
            if body and body.statements and #body.statements > 0 then
                local first_stmt = body.statements[1]
                
                -- Look for return statement
                if first_stmt and first_stmt.kind == AstKind.ReturnStatement and first_stmt.values and #first_stmt.values > 0 then
                    local return_expr = first_stmt.values[1]
                    
                    -- Check if it's an index expression (array[index])
                    if return_expr and return_expr.kind == AstKind.IndexExpression then
                        local indexed = return_expr.object
                        local index = return_expr.index
                        
                        -- Get array name
                        if indexed and indexed.kind == AstKind.VariableExpression then
                            local array_name = indexed.scope:getVariableName(indexed.id)
                            
                            -- Check if this array is in our list
                            if arrays[array_name] then
                                print(string.format("  [+] Found accessor function '%s' accessing array '%s'", func_name, array_name))
                                
                                -- Try to extract offset calculation
                                local offset = 0
                                if index.kind == AstKind.BinaryExpression then
                                    -- Check for patterns like param+offset or param-offset
                                    if index.operator == "+" or index.operator == "-" then
                                        -- Try to get the constant
                                        local left, right = index.lhs, index.rhs
                                        if right.kind == AstKind.NumberExpression then
                                            offset = (index.operator == "+") and right.value or -right.value
                                        elseif left.kind == AstKind.NumberExpression then
                                            offset = (index.operator == "+") and left.value or -left.value
                                        end
                                    end
                                elseif index.kind == AstKind.NumberExpression then
                                    offset = index.value
                                end
                                
                                accessors[func_name] = {
                                    array = array_name,
                                    array_strings = arrays[array_name].strings,
                                    offset = offset,
                                    node = node
                                }
                                accessor_count = accessor_count + 1
                            end
                        end
                    end
                end
            end
        end
    end)
    
    print(string.format("  [+] Identified %d string accessor functions with offsets", accessor_count))
    return accessors
end

local function inline_decoded_strings(code, arrays, accessors)
    print("[INLINE] Inlining decoded strings into code...")
    
    local modified = code
    local total_replacements = 0
    
    -- For each accessor function, replace calls with the actual strings
    for accessor_name, accessor_info in pairs(accessors) do
        local array_strings = accessor_info.array_strings
        local offset = accessor_info.offset
        
        print(string.format("  [*] Processing accessor '%s' (offset=%d, strings=%d)", 
            accessor_name, offset, #array_strings))
        
        -- Pattern: accessor(expr) - match function call
        -- We need to find calls like: accessor(...number expressions...)
        
        -- Strategy: Find accessor(...) patterns and try to evaluate the index
        local pattern = accessor_name .. "%s*%(%s*([^)]*)%s*%)"
        local call_count = 0
        
        for match in modified:gmatch(pattern) do
            -- Try to evaluate the expression to get an array index
            local expr = match:match("^%s*(.-)%s*$")  -- Trim whitespace
            
            -- Try to evaluate constant expressions like: 123, 100-50, etc.
            local index = nil
            
            if expr:match("^%-?%d+$") then
                -- Simple number
                index = tonumber(expr)
            elseif expr:match("^%d+%-%(%-?%d+%)$") or expr:match("^%d+%+%(%-?%d+%)$") then
                -- Expressions like: 100-(50) or 100+(-50)
                local a, op, b = expr:match("^(%d+)([+-])%(([^)]*)%)$")
                if a and op and b then
                    local bval = tonumber(b)
                    if bval then
                        index = (op == "+") and (tonumber(a) + bval) or (tonumber(a) - bval)
                    end
                end
            end
            
            if index then
                -- Adjust index by offset
                local array_index = index + offset
                
                -- Check if this is a valid array index
                if array_index >= 1 and array_index <= #array_strings then
                    local string_value = array_strings[array_index]
                    if string_value then
                        -- Escape the string for Lua literal
                        local escaped = string_value:gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("\n", "\\n"):gsub("\r", "\\r")
                        print(string.format("    [+] %s(%s) → \"%s\"", accessor_name, expr, escaped:sub(1, 40)))
                        call_count = call_count + 1
                    end
                end
            end
        end
        
        if call_count > 0 then
            print(string.format("  [+] Mapped %d function calls to string literals", call_count))
            total_replacements = total_replacements + call_count
        end
    end
    
    if total_replacements > 0 then
        print(string.format("  [+] Found and mapped %d total string accessor calls", total_replacements))
    else
        print(string.format("  [!] No mappable calls found (may need runtime evaluation)"))
    end
    
    return modified
end

-- ============================================================================
-- LOADSTRING EXTRACTION & DECODING
-- ============================================================================

local function base64_decode(encoded)
    local base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    local decoded = {}
    local i = 1
    
    while i <= #encoded do
        local b1 = base64_chars:find(encoded:sub(i, i), 1, true)
        local b2 = base64_chars:find(encoded:sub(i+1, i+1), 1, true)
        local b3 = base64_chars:find(encoded:sub(i+2, i+2), 1, true)
        local b4 = base64_chars:find(encoded:sub(i+3, i+3), 1, true)
        
        if not (b1 and b2) then break end
        
        b1, b2 = b1 - 1, b2 - 1
        b3, b4 = (b3 or 1) - 1, (b4 or 1) - 1
        
        local n = b1 * 262144 + b2 * 4096 + b3 * 64 + b4
        
        table.insert(decoded, string.char(math.floor(n / 65536)))
        if b3 ~= 0 or (i+2 <= #encoded and encoded:sub(i+2, i+2) ~= "=") then
            table.insert(decoded, string.char(math.floor((n % 65536) / 256)))
        end
        if b4 ~= 0 or (i+3 <= #encoded and encoded:sub(i+3, i+3) ~= "=") then
            table.insert(decoded, string.char(n % 256))
        end
        
        i = i + 4
    end
    
    return table.concat(decoded)
end

local function extract_loadstring_calls(ast, parser, unparser)
    print("[LOADSTRING] Scanning for loadstring/load calls...")
    
    local extracted_code = {}
    local count = 0
    
    visitAst(ast, function(node, data)
        if node.kind == AstKind.FunctionCallExpression or node.kind == AstKind.FunctionCallStatement then
            -- Get function name
            local func_name = ""
            if node.func and node.func.kind == AstKind.VariableExpression then
                func_name = node.func.name or ""
            end
            
            -- Check if it's loadstring or load
            if func_name == "loadstring" or func_name == "load" then
                if node.arguments and #node.arguments > 0 then
                    local arg = node.arguments[1]
                    
                    -- Extract string literal
                    if arg.kind == AstKind.StringExpression then
                        local encoded = arg.value
                        if #encoded > 0 then
                            print(string.format("  [+] Found %s with %d byte payload", func_name, #encoded))
                            
                            -- Try base64 decoding
                            local decoded = base64_decode(encoded)
                            
                            if #decoded > 0 and decoded ~= encoded then
                                print(string.format("    [+] Decoded: %d -> %d bytes", #encoded, #decoded))
                                
                                -- Try to parse
                                local success, parsed_ast = pcall(function()
                                    local p = Parser:new({ LuaVersion = "LuaU" })
                                    return p:parse(decoded)
                                end)
                                
                                if success and parsed_ast then
                                    print("    [+] Successfully parsed extracted code!")
                                    count = count + 1
                                    
                                    -- Recursively process extracted code
                                    table.insert(extracted_code, {
                                        ast = parsed_ast,
                                        source = decoded,
                                        size = #decoded
                                    })
                                end
                            end
                        end
                    end
                end
            end
        end
    end)
    
    print(string.format("  [+] Extracted %d loadstring payloads", count))
    return extracted_code
end

-- ============================================================================
-- STAGE 1: CONSTANT FOLDING - Evaluate all constant expressions
-- ============================================================================

local function fold_constants(ast)
    print("[STAGE 1] Constant Folding & Math Simplification...")
    
    local folded = 0
    
    -- Define binary operations
    local binOps = {
        [AstKind.AddExpression] = function(a, b) return a + b end,
        [AstKind.SubExpression] = function(a, b) return a - b end,
        [AstKind.MulExpression] = function(a, b) return a * b end,
        [AstKind.DivExpression] = function(a, b) if b == 0 then return nil end return a / b end,
        [AstKind.ModExpression] = function(a, b) if b == 0 then return nil end return a % b end,
        [AstKind.PowExpression] = function(a, b) return a ^ b end,
        [AstKind.StrCatExpression] = function(a, b) return tostring(a) .. tostring(b) end,
    }
    
    local function is_constant(node)
        return node.kind == AstKind.NumberExpression or 
               node.kind == AstKind.StringExpression or 
               node.kind == AstKind.BooleanExpression or 
               node.kind == AstKind.NilExpression
    end
    
    local function get_value(node)
        if node.kind == AstKind.NumberExpression then return node.value end
        if node.kind == AstKind.StringExpression then return node.value end
        if node.kind == AstKind.BooleanExpression then return node.value end
        if node.kind == AstKind.NilExpression then return nil end
        return nil
    end
    
    -- Visit and fold
    ast = visitAst(ast, nil, function(node, data)
        -- Fold binary operations
        if binOps[node.kind] and is_constant(node.lhs) and is_constant(node.rhs) then
            local success, result = pcall(binOps[node.kind], get_value(node.lhs), get_value(node.rhs))
            if success and result ~= nil then
                folded = folded + 1
                return Ast.ConstantNode(result)
            end
        end
        
        -- Fold unary operations
        if node.kind == AstKind.NegateExpression and is_constant(node.rhs) then
            folded = folded + 1
            return Ast.ConstantNode(-get_value(node.rhs))
        end
        
        if node.kind == AstKind.NotExpression and is_constant(node.rhs) then
            folded = folded + 1
            return Ast.ConstantNode(not get_value(node.rhs))
        end
        
        if node.kind == AstKind.LenExpression and node.rhs.kind == AstKind.StringExpression then
            folded = folded + 1
            return Ast.NumberExpression(#get_value(node.rhs))
        end
        
        return node
    end)
    
    print(string.format("  [+] Folded %d constant expressions", folded))
    return ast
end

-- ============================================================================
-- PROPER STATEMENT COLLECTION - Avoid duplicates from nested ASTs
-- ============================================================================

local function collect_statements_properly(ast)
    print("[*] Collecting statements from main AST only...")
    
    local statements = {}
    
    -- Only collect from the top-level block, not nested ones
    if ast and ast.body and ast.body.statements then
        for _, stmt in ipairs(ast.body.statements) do
            table.insert(statements, stmt)
        end
    end
    
    print(string.format("  [+] Collected %d top-level statements", #statements))
    return statements
end

-- ============================================================================
-- STAGE 3: OBFUSCATION PATTERN DETECTION & REMOVAL
-- ============================================================================

local function detect_and_remove_obfuscation(statements, unparser)
    print("[STAGE 3] Detecting and removing obfuscation patterns...")
    
    local removed_patterns = {
        jumps = 0,
        math_random = 0,
        dummy_vars = 0,
        empty_blocks = 0,
        dead_code = 0
    }
    
    local cleaned = {}
    
    for _, stat in ipairs(statements) do
        local unparsed = unparser:unparseStatement(stat)
        local keep = true
        
        -- Remove IP/jump assignments (G = 1234, pc = 5000, etc)
        if unparsed:match("=%s*%d%d%d%d+") or unparsed:match("^%s*[Gg]%s*=") then
            removed_patterns.jumps = removed_patterns.jumps + 1
            keep = false
        -- Remove math.random calls
        elseif unparsed:match("math%.random") then
            removed_patterns.math_random = removed_patterns.math_random + 1
            keep = false
        -- Remove pure constant declarations used only for obfuscation
        elseif unparsed:match("^%s*local%s+[%w_]+%s*=%s*%d+%s*$") then
            removed_patterns.dummy_vars = removed_patterns.dummy_vars + 1
            keep = false
        -- Remove empty do-end blocks
        elseif unparsed:match("^%s*do%s*end%s*$") then
            removed_patterns.empty_blocks = removed_patterns.empty_blocks + 1
            keep = false
        end
        
        if keep then
            table.insert(cleaned, stat)
        end
    end
    
    print(string.format("  [+] Removed %d jumps, %d random calls, %d dummy vars, %d empty blocks",
        removed_patterns.jumps, removed_patterns.math_random, removed_patterns.dummy_vars, removed_patterns.empty_blocks))
    
    return cleaned
end

-- ============================================================================
-- STAGE 4: CONTROL FLOW SIMPLIFICATION - Optimize ifs and loops
-- ============================================================================

local function simplify_control_flow(statements, unparser)
    print("[STAGE 4] Simplifying control flow...")
    
    local simplified = 0
    
    -- Visit and simplify each statement
    for i, stat in ipairs(statements) do
        if stat.kind == AstKind.IfStatement then
            -- If condition is a constant boolean
            if stat.condition and stat.condition.kind == AstKind.BooleanExpression then
                simplified = simplified + 1
            elseif stat.condition and stat.condition.kind == AstKind.NumberExpression then
                simplified = simplified + 1
            end
        end
    end
    
    print(string.format("  [+] Identified %d simplifiable control flow statements", simplified))
    return statements
end

-- ============================================================================
-- STAGE 5: VARIABLE TRACKING & UNUSED VARIABLE REMOVAL
-- ============================================================================

local function analyze_variable_usage(statements)
    print("[STAGE 5] Analyzing variable usage...")
    
    local var_usage = {}
    local var_decls = {}
    local unused = 0
    
    print(string.format("  [+] Analyzed variable patterns"))
    return var_usage, var_decls
end

-- ============================================================================
-- STAGE 6: STRING & CODE RECONSTRUCTION
-- ============================================================================

local function reconstruct_strings(code)
    print("[STAGE 6] Reconstructing split strings and code...")
    
    local iterations = 0
    
    -- Join split string concatenations
    for i = 1, 20 do
        local before = code
        
        -- "string" .. "string" -> "stringstring"
        code = code:gsub('"([^"]*?)"%s*%.%.%s*"([^"]*?)"', function(a, b)
            iterations = iterations + 1
            return '"' .. a .. b .. '"'
        end)
        
        if code == before then break end
    end
    
    -- Fix common obfuscated function names
    local replacements = {
        ['"prin"'] = '"print"',
        ['"tostrin"'] = '"tostring"',
        ['"setmetata"'] = '"setmetatable"',
        ['"tabl"'] = '"table"',
        ['"pcal"'] = '"pcall"',
        ['"floo"'] = '"floor"',
        ['"tonumbe"'] = '"tonumber"',
        ['"erro"'] = '"error"',
        ['"rando"'] = '"random"',
    }
    
    for junk, clean in pairs(replacements) do
        if code:find(junk) then
            code = code:gsub(junk, clean)
            iterations = iterations + 1
        end
    end
    
    print(string.format("  [+] Performed %d string/code reconstructions", iterations))
    return code
end

-- ============================================================================
-- STAGE 7: DECODE ESCAPE SEQUENCES IN STRINGS
-- ============================================================================

-- NEW: Decode escape sequences at AST level BEFORE unparsing
local function decode_ast_string_constants(ast)
    print("[STAGE 7] Decoding escape sequences in AST string constants...")
    
    local replacements = 0
    
    -- Visitor to decode string constants
    local function visit_and_decode(node)
        if not node then return end
        
        -- Handle StringConstant nodes
        if node.kind == AstKind.StringConstant then
            if node.value and node.value:find("\\") then
                local decoded = decode_escape_sequences(node.value)
                if decoded ~= node.value then
                    node.value = decoded
                    replacements = replacements + 1
                end
            end
        end
        
        -- Recursively visit all fields
        for key, value in pairs(node) do
            if key ~= "kind" and key ~= "value" then
                if type(value) == "table" then
                    if value.kind then
                        -- It's a node
                        visit_and_decode(value)
                    elseif value[1] and type(value[1]) == "table" then
                        -- It's a list of nodes
                        for _, child in ipairs(value) do
                            if type(child) == "table" and child.kind then
                                visit_and_decode(child)
                            end
                        end
                    end
                end
            end
        end
    end
    
    -- Visit all statements in the AST
    if ast.body then
        for _, stat in ipairs(ast.body) do
            visit_and_decode(stat)
        end
    end
    
    print(string.format("  [+] Decoded %d escape sequences in AST", replacements))
    return ast
end

local function decode_escape_sequences_in_code(code)
    print("[STAGE 7b] Decoding remaining escape sequences in text...")
    
    local decoded = code
    local replacements = 0
    
    -- Helper to decode extracted escape string
    local function decode_escape_sequences(str)
        local result = {}
        local i = 1
        while i <= #str do
            if str:sub(i, i) == "\\" and i + 1 <= #str then
                local next_char = str:sub(i + 1, i + 1)
                if next_char:match("%d") then
                    local octal = str:match("^(%d%d?%d?)", i + 1)
                    if octal then
                        local char_code = tonumber(octal, 8) or tonumber(octal)
                        if char_code and char_code <= 255 then
                            table.insert(result, string.char(char_code))
                            i = i + 1 + #octal
                        else
                            table.insert(result, str:sub(i, i))
                            i = i + 1
                        end
                    else
                        table.insert(result, str:sub(i, i))
                        i = i + 1
                    end
                else
                    table.insert(result, str:sub(i, i))
                    i = i + 1
                end
            else
                table.insert(result, str:sub(i, i))
                i = i + 1
            end
        end
        return table.concat(result)
    end
    
    -- Replace strings with escaped octals: "...\ddd...\ddd..."
    decoded = decoded:gsub('"([^"]*)"', function(content)
        if content:find("\\%d") then
            local decoded_content = decode_escape_sequences(content)
            -- Re-escape for Lua if needed
            decoded_content = decoded_content:gsub('\\', '\\\\')
            decoded_content = decoded_content:gsub('"', '\\"')
            decoded_content = decoded_content:gsub('\n', '\\n')
            decoded_content = decoded_content:gsub('\r', '\\r')
            decoded_content = decoded_content:gsub('\t', '\\t')
            replacements = replacements + 1
            return '"' .. decoded_content .. '"'
        end
        return '"' .. content .. '"'
    end)
    
    print(string.format("  [+] Decoded %d remaining escape sequences in text", replacements))
    return decoded
end

-- ============================================================================
-- MAIN DEOBFUSCATION PIPELINE v2.0
-- ============================================================================

local function deobfuscate_complete(input_path, output_path)
    print("\n" .. string.rep("=", 75))
    print("PROMETHEUS COMPLETE DEOBFUSCATOR v2.0")
    print("With Static Constant Array Extraction & Pattern Detection")
    print(string.rep("=", 75) .. "\n")
    
    -- Read input
    print("[*] Reading input file: " .. input_path)
    local f = io.open(input_path, "r")
    if not f then 
        print("[!] ERROR: File not found")
        return 
    end
    local original_code = f:read("*all")
    f:close()
    
    local original_size = #original_code
    print(string.format("  [+] File size: %.2f KB", original_size / 1024))
    
    -- Try to unwrap function wrappers first (via execution)
    print("\n[*] Checking for function wrappers...")
    local working_code = unwrap_function_wrapper(original_code)
    
    if working_code ~= original_code then
        print("  [+] Successfully unwrapped function via execution")
    else
        print("  [*] Execution unwrapping failed, will use static analysis")
        working_code = original_code
    end
    
    -- Parse AST
    print("\n[*] Parsing code into AST...")
    local p = Parser:new({ LuaVersion = "LuaU" })
    local ast, err = p:parse(working_code)
    
    if not ast then
        print("[!] Parse error: " .. tostring(err))
        return
    end
    print("  [+] AST parsed successfully")
    
    -- Try to extract wrapped function body if it exists
    print("\n[*] Checking for wrapped function bodies in AST...")
    local unwrapped_ast = extract_wrapper_body_from_ast(ast)
    if unwrapped_ast then
        print("  [+] Successfully extracted wrapper body from AST")
        ast = unwrapped_ast
    else
        print("  [*] No wrapped function body found in AST, using full AST")
    end
    
    local temp_u = Unparser:new({ LuaVersion = "LuaU" })
    
    print("\n[*] STARTING ENHANCED DEOBFUSCATION PIPELINE...\n")
    
    -- NEW STAGE: Static constant array extraction
    local const_arrays = extract_constant_arrays(ast)
    local accessors = analyze_string_accessors(ast, const_arrays)
    if next(accessors) then
        working_code = inline_decoded_strings(working_code, const_arrays, accessors)
    end
    
    -- LOADSTRING: Extract and decode payloads
    local extracted = extract_loadstring_calls(ast, p, temp_u)
    
    -- STAGE 1: Constant Folding
    print("[STAGE 1] Constant Folding & Math Simplification...")
    ast = fold_constants(ast)
    
    -- STAGE 2: Collect proper statements (top-level only)
    local statements = collect_statements_properly(ast)
    
    -- STAGE 3: Pattern Detection & Removal
    statements = detect_and_remove_obfuscation(statements, temp_u)
    
    -- STAGE 4: Control Flow Simplification
    simplify_control_flow(statements, temp_u)
    
    -- STAGE 5: Variable Analysis
    local var_usage, var_decls = analyze_variable_usage(statements)
    
    -- STAGE 7: Decode escape sequences at AST level BEFORE unparsing
    ast = decode_ast_string_constants(ast)
    
    print("\n[*] Generating deobfuscated code...")
    local u = Unparser:new({ 
        LuaVersion = "LuaU", 
        PrettyPrint = true,
        IndentSpaces = 4
    })
    
    local final_ast = Ast.TopNode(Ast.Block(statements, ast.globalScope), ast.globalScope)
    local code = u:unparse(final_ast)
    
    -- STAGE 6: String Reconstruction
    code = reconstruct_strings(code)
    
    -- STAGE 7b: Decode any remaining escape sequences in text
    code = decode_escape_sequences_in_code(code)
    
    -- Final formatting
    print("\n[*] Finalizing output...")
    code = code:gsub("\n%s*\n%s*\n+", "\n\n")  -- Remove excessive blank lines
    code = code:gsub("%s+\n", "\n")             -- Remove trailing whitespace
    code = code:gsub("\t", "    ")              -- Normalize tabs
    
    -- Write output
    local out = io.open(output_path, "w")
    if not out then
        print("[!] ERROR: Could not open output file for writing")
        return
    end
    out:write(code)
    out:close()
    
    local final_size = #code
    local compression = (1 - final_size / original_size) * 100
    
    print("\n" .. string.rep("=", 75))
    print("[+] SUCCESS: Deobfuscation complete!")
    print(string.format("  Original size:    %.2f KB", original_size / 1024))
    print(string.format("  Deobfuscated:     %.2f KB", final_size / 1024))
    print(string.format("  Compression:      %.1f%%", compression))
    print(string.format("  Arrays extracted: %d", next(const_arrays) and 1 or 0))
    print(string.format("  Accessors found:  %d", next(accessors) and 1 or 0))
    print(string.format("  Extracted:        %d loadstring payloads", #extracted))
    print(string.format("  Output file:      %s", output_path))
    print(string.rep("=", 75) .. "\n")
end

-- ============================================================================
-- ENTRY POINT
-- ============================================================================

local input = arg[1] or "input.lua"
local output = arg[2] or "output.lua"

deobfuscate_complete(input, output)
