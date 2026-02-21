local Lifter = {
    State = {
        IsEnabled = false,
        UI = {},
        Connections = {},
        IsLifting = false,
        VFS_Cache = {},
        VFS_Loading = {},
        VFS_Base = "https://raw.githubusercontent.com/zukatech1/Lifter/main/src/"
    },
    Config = {
        ACCENT = Color3.fromRGB(0, 255, 255),
        BG = Color3.fromRGB(20, 20, 20),
        LIFT_COLOR = Color3.fromRGB(170, 0, 255),
        KEYWORDS = {"and", "break", "do", "else", "elseif", "end", "false", "for", "function", "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while", "execute", "syn", "HttpGet", "HttpPost"},
        GLOBALS = {"getrawmetatable", "game", "Workspace", "script", "math", "string", "table", "print", "wait", "Instance", "Vector3", "CFrame", "Enum", "loadstring", "getgenv", "getrenv", "getreg", "getgc"},
        REMOTES = {"FireServer", "InvokeServer"},
        TOKENS = {["="]=true, ["."]=true, [","]=true, ["("]=true, [")"]=true, ["["]=true, ["]"]=true, ["{"]=true, ["}"]=true, [":"]=true, ["*"]=true, ["/"]=true, ["+"]=true, ["-"]=true, ["%"]=true, [";"]=true, ["~"]=true}
    },
    Services = {}
}
local function InitializeServices()
    local serviceNames = {"Players", "CoreGui", "UserInputService", "RunService", "TextService", "HttpService"}
    for _, serviceName in ipairs(serviceNames) do
        Lifter.Services[serviceName] = game:GetService(serviceName)
    end
end
local function DoNotif(message, notifType)
    local StarterGui = game:GetService("StarterGui")
    local notifIcon = "rbxasset://textures/ui/ErrorIcon.png"
    if notifType == 1 then
        notifIcon = "rbxasset://textures/ui/success.png"
    elseif notifType == 2 then
        notifIcon = "rbxasset://textures/ui/InfoIcon.png"
    elseif notifType == 3 then
        notifIcon = "rbxasset://textures/ui/ErrorIcon.png"
    end
    StarterGui:SetCore("SendNotification", {
        Title = "Zukas Lifter",
        Text = message,
        Icon = notifIcon,
        Duration = 3
    })
end
function Lifter:_vRequire(modulePath)
    local state = self.State
    if state.VFS_Cache[modulePath] then
        return state.VFS_Cache[modulePath]
    end
    if state.VFS_Loading[modulePath] then
        return state.VFS_Loading[modulePath]
    end
    local internalPath = modulePath:gsub("%.", "/") .. ".lua"
    local url = state.VFS_Base .. internalPath
    local success, content = pcall(game.HttpGet, game, url)
    if not success or content:find("404: Not Found") then
        local fallbackUrl = "https://raw.githubusercontent.com/zukatech1/Lifter/main/" .. internalPath
        success, content = pcall(game.HttpGet, game, fallbackUrl)
    end
    if not success or content:find("404: Not Found") then
        warn("--> [VFS] Resolution Failed: " .. modulePath)
        return nil
    end
    local func, err = loadstring(content, "@VFS/" .. modulePath)
    if not func then
        warn("--> [VFS] Syntax Error in " .. modulePath .. ": " .. err)
        return nil
    end
    local modulePlaceholder = {}
    state.VFS_Loading[modulePath] = modulePlaceholder
    local env = getfenv(func)
    env.require = function(path) return self:_vRequire(path) end
    env.arg = {}
    env.print = function(...) print("[LIFTER]:", ...) end
    setfenv(func, env)
    local result = func()
    local finalData = result or modulePlaceholder
    state.VFS_Cache[modulePath] = finalData
    state.VFS_Loading[modulePath] = nil
    return finalData
end
function Lifter:_initializeLifter()
    self.State.VFS_Cache = {}
    self.State.VFS_Loading = {}
    local Parser = self:_vRequire("prometheus.parser")
    local Ast = self:_vRequire("prometheus.ast")
    local VisitAst = self:_vRequire("prometheus.visitast")
    local Unparser = self:_vRequire("prometheus.unparser")
    return {
        Parser = Parser,
        Ast = Ast,
        VisitAst = VisitAst,
        Unparser = Unparser
    }
end
function Lifter:_process(str, keywordList)
    local K = {}
    for _, v in pairs(keywordList) do K[v] = true end
    local S = str:gsub(".", function(c) return self.Config.TOKENS[c] and " " or c end)
    S = S:gsub("%S+", function(c) return K[c] and c or (" "):rep(#c) end)
    return S
end
function Lifter:_update()
    local ui = self.State.UI
    if not ui.Source then return end
    local text = ui.Source.Text:gsub("\r", ""):gsub("\t", "    ")
    local textHeight = self.Services.TextService:GetTextSize(text, 14, Enum.Font.Code, Vector2.new(ui.EditorScroll.AbsoluteSize.X - 40, math.huge)).Y
    local finalHeight = math.max(textHeight + 50, ui.EditorScroll.AbsoluteSize.Y)
    ui.EditorScroll.CanvasSize = UDim2.fromOffset(0, finalHeight)
    ui.Source.Size = UDim2.new(1, -40, 0, finalHeight)
    ui.Keywords.Text = self:_process(text, self.Config.KEYWORDS)
    ui.Globals.Text = self:_process(text, self.Config.GLOBALS)
    ui.Remotes.Text = self:_process(text, self.Config.REMOTES)
    local _, lineCount = text:gsub("\n", "")
    ui.Lines.Text = ""
    for i = 1, lineCount + 1 do
        ui.Lines.Text ..= i .. "\n"
    end
end
function Lifter:CreateUI()
    if self.State.UI.Main then self.State.UI.Main.Visible = true return end
    local sg = Instance.new("ScreenGui", self.Services.CoreGui)
    sg.Name = "Zuka_RC7_Editor"
    sg.ResetOnSpawn = false
    local main = Instance.new("Frame", sg)
    main.Size = UDim2.fromOffset(600, 420)
    main.Position = UDim2.fromScale(0.5, 0.5)
    main.AnchorPoint = Vector2.new(0.5, 0.5)
    main.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
    main.BackgroundTransparency = 0.2
    main.BorderSizePixel = 1
    main.BorderColor3 = self.Config.ACCENT
    main.ClipsDescendants = true
    main.Active = true
    local header = Instance.new("Frame", main)
    header.Size = UDim2.new(1, 0, 0, 30)
    header.BackgroundColor3 = Color3.fromRGB(255, 85, 127)
    header.BorderSizePixel = 0
    local title = Instance.new("TextLabel", header)
    title.Size = UDim2.new(1, -60, 1, 0)
    title.Position = UDim2.fromOffset(10, 0)
    title.Text = "Zukas Lifter."
    title.TextColor3 = self.Config.ACCENT
    title.Font = Enum.Font.Code
    title.TextSize = 14
    title.TextXAlignment = Enum.TextXAlignment.Left; title.BackgroundTransparency = 1
    local close = Instance.new("TextButton", header)
    close.Size = UDim2.fromOffset(30, 30)
    close.Position = UDim2.new(1, -30, 0, 0)
    close.Text = "X"; close.TextColor3 = Color3.new(1,0,0); close.BackgroundTransparency = 1
    close.MouseButton1Click:Connect(function() sg:Destroy(); self.State.UI = {} end)
    local scroll = Instance.new("ScrollingFrame", main)
    scroll.Size = UDim2.new(1, -10, 1, -85)
    scroll.Position = UDim2.fromOffset(5, 35)
    scroll.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
    scroll.BackgroundTransparency = 0.4
    scroll.BorderSizePixel = 1
    scroll.BorderColor3 = Color3.fromRGB(50, 50, 50)
    scroll.ScrollBarThickness = 4
    scroll.ScrollBarImageColor3 = self.Config.ACCENT
    local lines = Instance.new("TextLabel", scroll)
    lines.Size = UDim2.new(0, 30, 1, 0)
    lines.BackgroundColor3 = Color3.fromRGB(25, 25, 25)
    lines.BorderSizePixel = 0
    lines.Text = "1"; lines.TextColor3 = Color3.fromRGB(100, 100, 100)
    lines.Font = Enum.Font.Code; lines.TextSize = 14; lines.TextYAlignment = "Top"
    local source = Instance.new("TextBox", scroll)
    source.Size = UDim2.new(1, -35, 1, 0)
    source.Position = UDim2.fromOffset(35, 0)
    source.BackgroundTransparency = 1
    source.TextColor3 = Color3.fromRGB(220, 220, 220)
    source.Font = Enum.Font.Code
    source.TextSize = 14
    source.TextXAlignment = Enum.TextXAlignment.Left; source.TextYAlignment = "Top"
    source.MultiLine = true; source.ClearTextOnFocus = false
    source.Text = ""
    local function mkOverlay(name, color)
        local l = Instance.new("TextLabel", source)
        l.Name = name; l.Size = UDim2.fromScale(1, 1); l.BackgroundTransparency = 1
        l.Font = Enum.Font.Code; l.TextSize = 14; l.TextXAlignment = "Left"; l.TextYAlignment = "Top"
        l.TextColor3 = color; l.Text = ""; l.ZIndex = 3
        return l
    end
    local kw = mkOverlay("Keywords", Color3.fromRGB(255, 80, 80))
    local gb = mkOverlay("Globals", Color3.fromRGB(80, 180, 255))
    local rm = mkOverlay("Remotes", Color3.fromRGB(0, 255, 150))
    local footer = Instance.new("Frame", main)
    footer.Size = UDim2.new(1, 0, 0, 45)
    footer.Position = UDim2.new(0, 0, 1, -45)
    footer.BackgroundColor3 = Color3.fromRGB(25, 25, 25)
    footer.BorderSizePixel = 0
    local function mkBtn(text, pos, color, cb)
        local b = Instance.new("TextButton", footer)
        b.Size = UDim2.fromOffset(110, 30)
        b.Position = pos
        b.BackgroundColor3 = Color3.fromRGB(40, 40, 40)
        b.BorderSizePixel = 1; b.BorderColor3 = color
        b.Text = text; b.TextColor3 = color; b.Font = Enum.Font.Code; b.TextSize = 13
        b.MouseButton1Click:Connect(cb)
        return b
    end
    mkBtn("EXECUTE", UDim2.fromOffset(10, 7), self.Config.ACCENT, function()
        local f, e = loadstring(source.Text)
        if f then task.spawn(f); DoNotif("Executed.", 1) else warn(e); DoNotif("Syntax Error", 2) end
    end)
    mkBtn("LIFT (PROM)", UDim2.fromOffset(130, 7), self.Config.LIFT_COLOR, function()
        if self.State.IsLifting then return end
        self.State.IsLifting = true
        task.spawn(function()
            local _old_info = debug.getinfo
            getgenv().debug.getinfo = function(f, ...)
                local res = _old_info(f, ...)
                if res and res.source and res.source:find("VFS") then
                    res.source = "=[C]"
                end
                return res
            end
            local components = self:_initializeLifter()
            if not components.Parser then
                self.State.IsLifting = false
                return DoNotif("VFS Error. Check F9.", 3)
            end
            local inputCode = source.Text
            if #inputCode == 0 then
                self.State.IsLifting = false
                return DoNotif("Source empty.", 2)
            end
            DoNotif("Lifting: Analyzing AST...", 2)
            local success, ast = pcall(function()
                local p = components.Parser:new({ LuaVersion = "LuaU" })
                return p:parse(inputCode)
            end)
            if not success or not ast then
                warn("--> [Lifter] Fatal Error: " .. tostring(ast))
                self.State.IsLifting = false
                return DoNotif("Deobfuscation Failed.", 3)
            end
            local u = components.Unparser:new({ LuaVersion = "LuaU", PrettyPrint = true, IndentSpaces = 4 })
            local liftedCode = u:unparse(ast)
            liftedCode = liftedCode:gsub('"([^"]*)"%s*%.%.%s*"([^"]*)"', '"%1%2"')
            source.Text = liftedCode
            self:_update()
            self.State.IsLifting = false
            DoNotif("Code Lifted.", 2)
            getgenv().debug.getinfo = _old_info
        end)
    end)
    mkBtn("CLEAR", UDim2.fromOffset(250, 7), Color3.fromRGB(255, 150, 0), function()
        source.Text = ""
    end)
    source:GetPropertyChangedSignal("Text"):Connect(function()
        self:_update()
    end)
    local dragging, dragStart, startPos
    header.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1 then
            dragging, dragStart, startPos = true, input.Position, main.Position
        end
    end)
    self.Services.UserInputService.InputChanged:Connect(function(input)
        if dragging and input.UserInputType == Enum.UserInputType.MouseMovement then
            local delta = input.Position - dragStart
            main.Position = UDim2.new(startPos.X.Scale, startPos.X.Offset + delta.X, startPos.Y.Scale, startPos.Y.Offset + delta.Y)
        end
    end)
    self.Services.UserInputService.InputEnded:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1 then dragging = false end
    end)
    self.State.UI = {Main = main, Source = source, EditorScroll = scroll, Lines = lines, Keywords = kw, Globals = gb, Remotes = rm}
    DoNotif("Forensic IDE Ready.", 2)
end
function Lifter:Initialize()
    InitializeServices()
    self:CreateUI()
end
Lifter:Initialize()
return Lifter
