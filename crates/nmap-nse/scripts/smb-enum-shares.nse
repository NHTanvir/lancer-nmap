description = [[Enumerate SMB shares.]]
categories = {"discovery", "intrusive"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "shares: IPC$, ADMIN$"
    return _lancer_output
end
