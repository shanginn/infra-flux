$TTL 24H
@     IN  SOA @       hostmaster.flowerworks.ru. (
  2   ; serial
  3H  ; refresh
  1H  ; retry
  1W  ; expire
  3H )    ; minimum

; Specify the nameserver
@     IN  NS          ns1.shanginn.io.
@     IN  NS          ns2.shanginn.io.

; Map the domain to an IP address
@     IN  A           185.221.212.224
*     IN  A           185.221.212.224

; Map 'www' and 'mail' subdomains to the same IP address
www   IN  A           185.221.212.224
mail  IN  A           185.221.212.224

; Set the IP address for the nameserver
ns1   IN  A           185.221.212.224
