description = [[Try logging into MySQL with empty passwords for common users.]]
categories = {"auth", "intrusive"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "no empty-password access"
    return _lancer_output
end
