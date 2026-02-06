description = [[List SMTP commands supported by the server via EHLO.]]
categories = {"default", "discovery", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "EHLO commands: STARTTLS AUTH"
    return _lancer_output
end
