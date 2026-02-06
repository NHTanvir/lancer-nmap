description = [[Modbus/TCP unit ID discovery.]]
categories = {"discovery", "ics", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "modbus discover"
    return _lancer_output
end
