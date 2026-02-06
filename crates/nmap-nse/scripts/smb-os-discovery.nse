description = [[Negotiate SMB to extract OS, Domain, Workgroup, NetBIOS name.]]
categories = {"default", "discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "SMB OS discovery"
    return _lancer_output
end
