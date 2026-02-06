description = [[Check for anonymous FTP login.]]
categories = {"default", "auth", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "anonymous FTP check"
    return _lancer_output
end
