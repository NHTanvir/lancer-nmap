description = [[Probe for AWS IMDS exposure via SSRF.]]
categories = {"vuln", "discovery"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "IMDS check"
    return _lancer_output
end
