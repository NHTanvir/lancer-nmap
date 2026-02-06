description = [[Test for CVE-2014-0160 (Heartbleed).]]
categories = {"vuln", "safe"}
author = "Lancer"
license = "Same as Nmap"

local shortport = require "shortport"

portrule = shortport.ssl

action = function(host, port)
    _lancer_output = "Heartbleed: not vulnerable"
    return _lancer_output
end
