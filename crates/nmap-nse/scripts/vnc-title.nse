description = [[Grab VNC server title.]]
categories = {"default", "discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "VNC title"
    return _lancer_output
end
