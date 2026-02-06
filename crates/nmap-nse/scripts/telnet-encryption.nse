description = [[Detect Telnet ENCRYPT option support.]]
categories = {"discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "ENCRYPT support"
    return _lancer_output
end
