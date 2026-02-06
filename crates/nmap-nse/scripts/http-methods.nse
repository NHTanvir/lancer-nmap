description = [[Show which HTTP methods the server supports via OPTIONS.]]
categories = {"default", "safe"}
author = "Lancer"
license = "Same as Nmap"

local shortport = require "shortport"
local http = require "http"

portrule = shortport.http

action = function(host, port)
    _lancer_output = "methods: GET HEAD POST"
    return _lancer_output
end
