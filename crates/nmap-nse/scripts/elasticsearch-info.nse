description = [[Elasticsearch root endpoint info.]]
categories = {"default", "discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "ES cluster info"
    return _lancer_output
end
