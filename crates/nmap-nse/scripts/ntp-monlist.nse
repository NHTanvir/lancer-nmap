description = [[NTP MON_GETLIST request; abusable for amplification.]]
categories = {"discovery", "intrusive"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "MON_GETLIST"
    return _lancer_output
end
