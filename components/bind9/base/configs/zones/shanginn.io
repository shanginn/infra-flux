$TTL 24H
@     IN  SOA @       hostmaster.shanginn.io. (
  2026061602       ; serial
  3H      ; refresh
  1H      ; retry
  1W      ; expire
  3H )    ; minimum

@          IN  NS          ns1.shanginn.io.
@          IN  NS          ns2.shanginn.io.

@          IN  A           84.247.177.201
ns1        IN  A           84.247.177.201
ns2        IN  A           185.221.212.224
ts         IN  A           185.221.212.224
teamspeak  IN  A           185.221.212.224
temporal.rubase IN A        185.221.212.224
*.rubase   IN  A           185.221.212.224
*          IN  A           84.247.177.201

@                  IN  MX  10      mail.shanginn.io.

;Reverse lookup for Name Server
10        IN  PTR         ns1.shanginn.io.

;PTR Record IP address to HostName
100       IN  PTR         www.shanginn.io.
150       IN  PTR         mail.shanginn.io.
