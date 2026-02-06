description = [[Test for ROCA (CVE-2017-15361) RSA keypair generation flaw.]]
categories = {"vuln", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "ROCA: not vulnerable"
    return _lancer_output
end
