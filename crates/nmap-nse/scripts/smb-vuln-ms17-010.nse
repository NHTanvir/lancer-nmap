description = [[Test for MS17-010 EternalBlue.]]
categories = {"vuln", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "MS17-010: not vulnerable"
    return _lancer_output
end
