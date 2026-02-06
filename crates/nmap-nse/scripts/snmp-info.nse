description = [[Extract sysDescr/uptime via SNMP.]]
categories = {"default", "discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "SNMP sysDescr"
    return _lancer_output
end
