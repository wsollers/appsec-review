-- Fixtures are scan-only data, never executed.

-- ruleid: appsec-review.lua.dynamic-code
local compiled = load(player_payload, "mod", "t", {})
-- ruleid: appsec-review.lua.dynamic-code
local legacy = loadstring(player_payload)
-- ruleid: appsec-review.lua.dynamic-code
RunString(player_payload)
-- ok: appsec-review.lua.dynamic-code
local saved = json.decode(player_payload)
-- A literal still introduces an execution capability.
-- ruleid: appsec-review.lua.dynamic-code
local literal = load("return 1")

-- ruleid: appsec-review.lua.file-code-loading
dofile(mod_path)
-- ruleid: appsec-review.lua.file-code-loading
local chunk = love.filesystem.load("mods/start.lua")
-- ruleid: appsec-review.lua.file-code-loading
local file_chunk = loadfile(mod_path, "t", {})
-- ok: appsec-review.lua.file-code-loading
local filename = "loadfile(mod_path)"

-- ruleid: appsec-review.lua.shell-execution
os.execute("tool " .. player_arg)
-- ruleid: appsec-review.lua.shell-execution
local pipe = io.popen(command, "r")
-- ok: appsec-review.lua.shell-execution
local status = host.run_allowed_tool(tool_id)

-- ruleid: appsec-review.lua.native-code
local ffi = require("ffi")
-- ruleid: appsec-review.lua.native-code
local library = package.loadlib(native_path, "init")
-- ruleid: appsec-review.lua.native-code
ffi.C.system(command)
-- ruleid: appsec-review.lua.native-code
ffi.cdef("int system(const char *command);")
-- ok: appsec-review.lua.native-code
local settings = require("settings")

-- ruleid: appsec-review.lua.debug-capability
debug.setupvalue(callback, 1, globals)
-- ruleid: appsec-review.lua.debug-capability
debug.sethook()
-- ruleid: appsec-review.lua.debug-capability
local registry = debug.getregistry()
-- ok: appsec-review.lua.debug-capability
local trace = debug.traceback()

-- ruleid: appsec-review.lua.environment-escape
setfenv(callback, environment)
-- ruleid: appsec-review.lua.environment-escape
setmetatable(environment, { __index = _G })
-- ruleid: appsec-review.lua.environment-escape
local globals = getfenv(0)
-- ok: appsec-review.lua.environment-escape
setmetatable(environment, { __index = allowed_api })

-- ruleid: appsec-review.lua.module-search-mutation
package.path = mod_root .. "/?.lua;" .. package.path
-- ruleid: appsec-review.lua.module-search-mutation
package.searchers[1] = mod_loader
-- ruleid: appsec-review.lua.module-search-mutation
table.insert(package.loaders, mod_loader)
-- ok: appsec-review.lua.module-search-mutation
local search_path = package.path

-- ruleid: appsec-review.lua.dynamic-module
local mod = require(player_module)
-- ruleid: appsec-review.lua.dynamic-module
include(player_script)
-- ok: appsec-review.lua.dynamic-module
local trusted = require("game.trusted")
-- ok: appsec-review.lua.dynamic-module
include("shared.lua")
-- ruleid: appsec-review.lua.dynamic-module
local asset = require(123456789)

-- ruleid: appsec-review.lua.global-dispatch
_G[player_action](player_value)
-- ruleid: appsec-review.lua.global-dispatch
_ENV[player_action](player_value)
-- ok: appsec-review.lua.global-dispatch
allowed_actions[player_action](validated_value)

-- ruleid: appsec-review.lua.dynamic-file-access
local input = io.open(player_path, "rb")
-- ruleid: appsec-review.lua.dynamic-file-access
os.remove(player_path)
-- ruleid: appsec-review.lua.dynamic-file-access
love.filesystem.write(player_path, data)
-- ruleid: appsec-review.lua.dynamic-file-access
file.Read(player_path, "DATA")
-- ok: appsec-review.lua.dynamic-file-access
local config = io.open("config/settings.json", "rb")
-- ok: appsec-review.lua.dynamic-file-access
love.filesystem.read("assets/default.json")

-- ruleid: appsec-review.lua.file-rename
os.rename(source_path, destination_path)
-- ok: appsec-review.lua.file-rename
local name = os.date("%Y")

-- ruleid: appsec-review.lua.sql-string-construction
sql.Query("SELECT * FROM players WHERE name = '" .. player_name .. "'")
-- ruleid: appsec-review.lua.sql-string-construction
database:execute("DELETE FROM items WHERE id = " .. item_id)
-- ruleid: appsec-review.lua.sql-string-construction
MySQL.Async.fetchAll("SELECT * FROM inventory WHERE owner = " .. owner, {}, callback)
-- ok: appsec-review.lua.sql-string-construction
database:execute("SELECT * FROM players WHERE id = ?", player_id)
-- ok: appsec-review.lua.sql-string-construction
sql.Query("SELECT * FROM players")

-- ruleid: appsec-review.lua.tls-verification-disabled
local insecure_tls = { mode = "client", verify = "none", protocol = "any" }
-- ruleid: appsec-review.lua.tls-verification-disabled
options.verify = "none"
-- ruleid: appsec-review.lua.tls-verification-disabled
local insecure_http = { ssl_verify = false }
-- ok: appsec-review.lua.tls-verification-disabled
local peer_tls = { verify = "peer" }

-- ruleid: appsec-review.lua.cleartext-http
http.request("http://updates.example.invalid/manifest")
-- ruleid: appsec-review.lua.cleartext-http
PerformHttpRequest('http://api.example.invalid/reward', callback)
-- ok: appsec-review.lua.cleartext-http
http.Fetch("https://updates.example.invalid/manifest", callback)
-- ok: appsec-review.lua.cleartext-http
local text = "http.request('http://example.invalid')"

-- ruleid: appsec-review.lua.predictable-random
local token = math.random(100000, 999999)
-- ruleid: appsec-review.lua.predictable-random
math.randomseed(os.time())
-- ruleid: appsec-review.lua.predictable-random
local cosmetic = love.math.random()
-- ok: appsec-review.lua.predictable-random
local secure_token = host.secure_random_bytes(32)

-- ruleid: appsec-review.lua.resource-amplification
local repeated = string.rep(payload, count)
-- ruleid: appsec-review.lua.resource-amplification
local unpacked = util.Decompress(compressed)
-- ruleid: appsec-review.lua.resource-amplification
local decoded = love.data.decompress("string", "zlib", compressed)
-- ok: appsec-review.lua.resource-amplification
local bounded = host.decompress_with_limit(compressed, 4096)

-- ruleid: appsec-review.lua.read-all
local contents = input:read("*a")
-- ruleid: appsec-review.lua.read-all
local stdin = io.read("a")
-- ruleid: appsec-review.lua.read-all
local response = socket:receive("*a")
-- ok: appsec-review.lua.read-all
local block = input:read(4096)

-- ruleid: appsec-review.lua.network-entrypoint
net.Receive("purchase", function(length, player)
    process_purchase(player)
end)
-- ruleid: appsec-review.lua.network-entrypoint
RegisterNetEvent("inventory:grant", on_grant)
-- ruleid: appsec-review.lua.network-entrypoint
remote.OnServerEvent:Connect(on_purchase)
-- ruleid: appsec-review.lua.network-entrypoint
remote.OnServerInvoke = on_purchase
-- ok: appsec-review.lua.network-entrypoint
local event_name = "RegisterNetEvent"

-- ruleid: appsec-review.lua.game-command
RunConsoleCommand("kick", player_name)
-- ruleid: appsec-review.lua.game-command
game.ConsoleCommand(command .. "\n")
-- ruleid: appsec-review.lua.game-command
ExecuteCommand(player_command)
-- ok: appsec-review.lua.game-command
host.perform_authorized_action(player, action)

-- Additional API variants and syntactic edge cases.
-- ruleid: appsec-review.lua.dynamic-code
RunStringEx(player_payload, "network")
-- ruleid: appsec-review.lua.dynamic-code
local other_chunk = CompileString(player_payload, "network")
-- ruleid: appsec-review.lua.file-code-loading
local gmod_chunk = CompileFile(mod_path)
-- ruleid: appsec-review.lua.native-code
local other_library = ffi.load(native_path)
-- ruleid: appsec-review.lua.debug-capability
local upvalue = debug.getupvalue(callback, 1)
-- ruleid: appsec-review.lua.debug-capability
debug.upvaluejoin(callback, 1, other_callback, 2)
-- ruleid: appsec-review.lua.debug-capability
local local_value = debug.getlocal(1, 1)
-- ruleid: appsec-review.lua.debug-capability
debug.setlocal(1, 1, value)
-- ruleid: appsec-review.lua.debug-capability
local hidden_meta = debug.getmetatable(object)
-- ruleid: appsec-review.lua.debug-capability
debug.setmetatable(object, replacement)
-- ruleid: appsec-review.lua.debug-capability
debug.debug()
-- ruleid: appsec-review.lua.environment-escape
environment.__index = _G
-- ruleid: appsec-review.lua.environment-escape
_ENV = _G
local environment_meta = {
    label = "sandbox",
    -- ruleid: appsec-review.lua.environment-escape
    __index = _G,
    __metatable = "locked"
}
-- ruleid: appsec-review.lua.module-search-mutation
package.cpath = native_root .. "/?.so"
-- ruleid: appsec-review.lua.module-search-mutation
package.searchers = custom_searchers
-- ruleid: appsec-review.lua.module-search-mutation
package.loaders = custom_loaders
-- ruleid: appsec-review.lua.module-search-mutation
package.loaders[1] = custom_loader
-- ruleid: appsec-review.lua.module-search-mutation
table.insert(package.searchers, 1, custom_loader)
-- ruleid: appsec-review.lua.dynamic-file-access
love.filesystem.read(player_path)
-- ruleid: appsec-review.lua.dynamic-file-access
love.filesystem.remove(player_path)
-- ruleid: appsec-review.lua.dynamic-file-access
file.Write(player_path, data)
-- ruleid: appsec-review.lua.dynamic-file-access
file.Delete(player_path)
-- ruleid: appsec-review.lua.sql-string-construction
database:exec("DELETE FROM items WHERE id = " .. item_id)
-- ruleid: appsec-review.lua.sql-string-construction
database:query("SELECT * FROM items WHERE owner = " .. owner)
-- ruleid: appsec-review.lua.sql-string-construction
MySQL.Async.execute("DELETE FROM items WHERE id = " .. item_id, {}, callback)
-- ruleid: appsec-review.lua.sql-string-construction
MySQL.query("SELECT * FROM items WHERE owner = " .. owner, {}, callback)
-- ruleid: appsec-review.lua.sql-string-construction
sql.Query(string.format("SELECT * FROM players WHERE name = '%s'", player_name))
-- ruleid: appsec-review.lua.sql-string-construction
database:execute(string.format("DELETE FROM players WHERE name = '%s'", player_name))
local tls_options = {
    mode = "client",
    -- ruleid: appsec-review.lua.tls-verification-disabled
    verify = "none",
    protocol = "any"
}
local http_options = {
    method = "GET",
    -- ruleid: appsec-review.lua.tls-verification-disabled
    ssl_verify = false,
    headers = {}
}
-- ruleid: appsec-review.lua.cleartext-http
http.Fetch("http://updates.example.invalid/", callback)
-- ruleid: appsec-review.lua.cleartext-http
http.Post("http://api.example.invalid/", data, callback)
-- ruleid: appsec-review.lua.predictable-random
love.math.setRandomSeed(os.time())
-- ruleid: appsec-review.lua.read-all
local other_contents = input:read("a")
-- ruleid: appsec-review.lua.read-all
local other_stdin = io.read("*a")
-- ruleid: appsec-review.lua.network-entrypoint
RegisterServerEvent("inventory:drop")

-- A bounded call remains an audit lead, not a claim of missing limits.
if count >= 0 and count <= 128 then
    -- ruleid: appsec-review.lua.resource-amplification
    local bounded_repeat = string.rep(".", count)
end
-- A handler with authorization still needs review; registration is not a defect.
-- ruleid: appsec-review.lua.network-entrypoint
net.Receive("admin", function(length, player)
    if not player:IsAdmin() then
        return
    end
    perform_admin_action(player)
end)
-- Constant paths are outside the dynamic-path rule, not certified safe.
-- ok: appsec-review.lua.dynamic-file-access
file.Write("settings.json", encoded_settings)
-- ok: appsec-review.lua.dynamic-file-access
os.remove("cache.tmp")
-- ok: appsec-review.lua.tls-verification-disabled
options.verify = "peer"
-- ok: appsec-review.lua.environment-escape
local restricted_meta = { label = "sandbox", __index = allowed_api }
-- ok: appsec-review.lua.module-search-mutation
local other_searcher = package.searchers[1]

-- ruleid: appsec-review.lua.tls-verification-disabled
http_options.ssl_verify = false
-- ruleid: appsec-review.lua.process-exit
os.exit(0)
-- ok: appsec-review.lua.process-exit
host.cancel_script(script_id)

-- None of these comments or strings should create matches.
-- os.execute(player_command)
-- loadstring(payload)()
local documentation = "debug.getregistry(); ffi.C.system(command)"
