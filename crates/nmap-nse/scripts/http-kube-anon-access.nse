description = [[Probe Kubernetes API anonymous access (anonymous-auth flag).]]
categories = {"discovery", "vuln"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "kube anon check"
    return _lancer_output
end
