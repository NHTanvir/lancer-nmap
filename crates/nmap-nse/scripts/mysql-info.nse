description = [[Negotiate MySQL handshake; emit version + capabilities + auth-plugin.]]
categories = {"default", "discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "MySQL handshake"
    return _lancer_output
end
