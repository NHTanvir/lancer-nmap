description = [[Enumerate common web app paths (admin panels, etc.).]]
categories = {"discovery", "intrusive"}
author = "Lancer"
license = "Same as Nmap"

local shortport = require "shortport"
local http = require "http"

portrule = shortport.http

action = function(host, port)
    _lancer_output = "scanned common paths"
    return _lancer_output
end
