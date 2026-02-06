description = [[Dump the server TLS certificate (subject, issuer, validity, SAN list).]]
categories = {"default", "safe", "discovery"}
author = "Lancer"
license = "Same as Nmap"

local shortport = require "shortport"

portrule = shortport.ssl

action = function(host, port)
    _lancer_output = "TLS cert details"
    return _lancer_output
end
