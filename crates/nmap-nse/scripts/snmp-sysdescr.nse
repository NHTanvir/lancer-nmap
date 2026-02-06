description = [[SNMP sysDescr.0 OID query.]]
categories = {"default", "discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "sysDescr (stub)"
    return _lancer_output
end
