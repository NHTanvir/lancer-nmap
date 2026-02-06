description = [[Print the SSH host key(s) and fingerprint.]]
categories = {"default", "safe", "discovery"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "ssh-rsa fingerprint"
    return _lancer_output
end
