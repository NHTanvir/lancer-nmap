description = [[Check whether the DNS server supports recursion.]]
categories = {"default", "discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "recursion: disabled"
    return _lancer_output
end
