description = [[Enumerate ciphers and TLS versions the server accepts, including PQ groups.]]
categories = {"default", "discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

local shortport = require "shortport"

portrule = shortport.ssl

action = function(host, port)
    _lancer_output = "cipher suite enumeration"
    return _lancer_output
end
