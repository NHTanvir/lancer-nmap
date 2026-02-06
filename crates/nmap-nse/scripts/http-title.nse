description = [[
Connects to an HTTP service and pulls the contents of the <title> element.
Lancer port of the upstream `http-title` NSE script.
]]

categories = {"default", "discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

local shortport = require "shortport"
local http = require "http"

portrule = shortport.http

action = function(host, port)
    local resp = http.get(host, port, "/")
    local title = "(no title)"
    if resp and resp.body then
        local m = resp.body:match("<title[^>]*>%s*(.-)%s*</title>")
        if m then title = m end
    end
    _lancer_output = "title=" .. title
    return _lancer_output
end
