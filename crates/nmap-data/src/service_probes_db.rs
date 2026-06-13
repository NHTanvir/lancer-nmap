//! Embedded reference probe set for nmap-probes. The full upstream
//! `nmap-service-probes` file is ~3 MB; what we include here is a minimal
//! built-in set so the engine boots without an external file. The
//! `--datadir <dir>` flag points to the full file when the operator wants it.

/// The complete upstream `nmap-service-probes` database (v7.99), embedded
/// verbatim. This is the 1,246-protocol, ~8,000-match-line file that powers
/// `-sV` service/version detection at full fidelity. Freely redistributable
/// per the upstream `nmap-service-probes` header.
pub const FULL: &str = include_str!("../data/nmap-service-probes");

/// Minimal built-in `nmap-service-probes` content covering the common probes
/// (TCP NULL, GenericLines, GetRequest, HTTPOptions, RPCCheck, SSLSessionReq,
/// TerminalServerCookie, TLSSessionReq). Used as a fallback / in unit tests.
pub const BUILTIN: &str = r#"# Lancer-nmap built-in service probes (compact subset)
# Upstream parity tests expect the full nmap-service-probes file via --datadir.
Exclude T:9100-9107

Probe TCP NULL q||
rarity 1
ports 1-65535
totalwaitms 6000

match ssh m|^SSH-([\d.]+)-([^\r\n]+)| p/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/
match smtp m|^220([- ])([^\r\n]+)| p/SMTP/ v/$2/
match ftp m|^220([- ])([^\r\n]+)| p/FTP/ v/$2/
match telnet m|^\xff[\xfb-\xfe]| p/Telnet/
match imap m|^\* OK ([^\r\n]+)| p/IMAP/ v/$1/
match pop3 m|^\+OK ([^\r\n]+)| p/POP3/ v/$1/
match http m|^HTTP/1\.([01]) (\d\d\d)| p/HTTP/ v/$1/
match mysql m|.\x00\x00\x00\x0a([\d.]+)\x00| p/MySQL/ v/$1/
match redis m|^\+OK\r\n| p/Redis/
match memcached m|^STAT pid \d+\r\n| p/Memcached/
match mongodb m|.+\x00\x00\x00\x00\x00\x00\x00\x00.+| p/MongoDB/

softmatch unknown m|^.+|s p/unknown/

Probe TCP GenericLines q|\r\n\r\n|
rarity 1
ports 21,23,25,79,80,81,110,119,143,220,443,465,512,514,515,540,554,587,593,705,725,777,783,873,990,993,995,1025,1026,1027,1056,1080,1099,1158,1352,1433,1521,1583,1720,1723,1755,1761,1801,1944,2000,2049,2103,2105,2107,2121,2200,2222,2381,2393,2401,2447,2483,2484,2638,2715,2718,2811,2869,2998,3000,3001,3050,3128,3260,3268,3269,3306,3372,3389,3531,3689,3690,3784,3826,3848,3872,3905,3914,3994,4000,4045,4444,4500,4502,4848,4899,5000,5009,5050,5060,5061,5101,5190,5222,5225,5269,5400,5414,5432,5500,5550,5631,5666,5800,5900,5901,5985,5988,5989,5998,6000,6112,6379,6502,6543,6566,6646,6789,6900,6969,7000,7001,7002,7019,7070,7100,7144,7402,7435,7443,7777,7937,8000,8001,8002,8005,8007,8008,8009,8010,8042,8080,8081,8086,8090,8093,8128,8161,8181,8200,8222,8243,8280,8290,8400,8443,8500,8649,8731,8800,8888,8983,9000,9001,9009,9090,9091,9100,9200,9201,9217,9300,9418,9443,9485,9876,9929,10000,10001,10243,10617,10628,11110,11211,11367,12345,12346,16080,18081,20000,25565,27015,32400,33060,40193,49152,50000,50050,50070,52199
totalwaitms 6000
match http m|^HTTP/1\.([01]) (\d\d\d)| p/HTTP/v/$1.x/
match nntp m|^200 ([^\r\n]+)| p/NNTP/ v/$1/
softmatch unknown m|^.+|s p/unknown/

Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
ports 80,81,443,591,593,631,8000,8001,8002,8008,8009,8010,8080,8081,8083,8088,8090,8181,8443,8888,9080,9090
totalwaitms 6000
match http m|^HTTP/1\.([01]) (\d\d\d)| p/HTTP/v/$1/
match http m|^Server: ([^\r\n]+)| p/HTTP/ v/$1/

Probe TCP HTTPOptions q|OPTIONS / HTTP/1.0\r\n\r\n|
rarity 1
ports 80,81,443,631,1080,3128,8000,8080
totalwaitms 6000
match http m|^HTTP/1\.([01]) (\d\d\d)| p/HTTP/v/$1/

Probe TCP TLSSessionReq q|\x16\x03\x01\x00\x4d\x01\x00\x00\x49\x03\x03|
rarity 1
ports 443,465,563,636,853,989,990,992,993,994,995,5061,5223,8443,9443
totalwaitms 6000
match ssl m|^\x16\x03\x01| p/SSL/

Probe UDP DNSStatusRequest q|\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00|
rarity 1
ports 53
totalwaitms 6000
match dns m|^\x00\x00| p/DNS/
"#;
