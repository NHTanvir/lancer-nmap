description = [[Query MikroTik WinBox admin service for RouterOS version.]]
categories = {"discovery", "iot", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "RouterOS version"
    return _lancer_output
end
