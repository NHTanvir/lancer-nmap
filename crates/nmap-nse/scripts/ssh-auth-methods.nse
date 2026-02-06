description = [[List SSH auth methods (password, publickey, keyboard-interactive).]]
categories = {"auth", "discovery"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "auth-methods: publickey,keyboard-interactive"
    return _lancer_output
end
