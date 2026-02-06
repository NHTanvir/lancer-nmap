description = [[Docker daemon /version endpoint.]]
categories = {"default", "discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "Docker version"
    return _lancer_output
end
