description = [[Enumerate ALPN protocols supported by the TLS server.]]
categories = {"default", "discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "ALPN: h2, http/1.1"
    return _lancer_output
end
