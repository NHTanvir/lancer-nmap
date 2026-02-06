description = [[Issue FTP SYST.]]
categories = {"default", "discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "SYST: UNIX Type: L8"
    return _lancer_output
end
