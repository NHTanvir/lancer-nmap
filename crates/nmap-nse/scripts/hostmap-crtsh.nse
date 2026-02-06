description = [[Pull subdomain candidates from crt.sh CT logs (verified subdomain only).]]
categories = {"discovery", "external", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "crt.sh hostmap"
    return _lancer_output
end
