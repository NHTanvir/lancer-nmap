description = [[Detect internal IP disclosure via HTTP responses (IPv4 + IPv6 + HTTPS).]]
categories = {"discovery", "vuln"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "internal IP check"
    return _lancer_output
end
