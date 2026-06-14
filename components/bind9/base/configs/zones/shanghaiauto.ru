$TTL 24H
@     IN  SOA @       hostmaster.shanghaiauto.ru. (
  2026060601   ; serial
  3H  ; refresh
  1H  ; retry
  1W  ; expire
  3H )    ; minimum

; Specify the nameserver
@     IN  NS          ns1.shanginn.io.
@     IN  NS          ns2.shanginn.io.

; Map the domain to an IP address
@     IN  A           31.76.43.200

; Map 'www' subdomain to the same IP address
www   IN  A           31.76.43.200

; Set the IP address for the nameserver
ns1   IN  A           185.221.212.224
