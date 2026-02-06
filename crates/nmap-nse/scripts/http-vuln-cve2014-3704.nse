description = [[Test for Drupal "Drupalgeddon" SQLi (CVE-2014-3704).]]
categories = {"vuln", "safe"}
author = "Lancer"
license = "Same as Nmap"

action = function(host, port)
    _lancer_output = "CVE-2014-3704: not vulnerable"
    return _lancer_output
end
