description = [[Attempt a DNS zone transfer (AXFR).]]
categories = {"discovery", "intrusive"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "AXFR refused"
    return _lancer_output
end
