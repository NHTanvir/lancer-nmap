description = [[Fetch /robots.txt and surface disallowed paths.]]
categories = {"default", "discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

local shortport = require "shortport"
local http = require "http"

portrule = shortport.http

action = function(host, port)
    _lancer_output = "fetched /robots.txt"
    return _lancer_output
end
