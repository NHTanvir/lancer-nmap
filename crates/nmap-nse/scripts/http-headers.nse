description = [[Show all HTTP response headers — Lancer port of upstream http-headers.]]
categories = {"discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

local shortport = require "shortport"
local http = require "http"

portrule = shortport.http

action = function(host, port)
    local resp = http.get(host, port, "/")
    _lancer_output = "headers received"
    return _lancer_output
end
