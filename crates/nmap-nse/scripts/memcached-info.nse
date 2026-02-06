description = [[Memcached STATS dump.]]
categories = {"default", "discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "STATS"
    return _lancer_output
end
