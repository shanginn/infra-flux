$TTL 24H
@     IN  SOA @       hostmaster.aufstaff.ru. (
  1   ; serial
  3H  ; refresh
  1H  ; retry
  1W  ; expire
  3H )    ; minimum

; Specify the nameserver
@     IN  NS          ns1.shanginn.io.
@     IN  NS          ns2.shanginn.io.

; Route the domain and web aliases to the RU gate
@     IN  A           2.26.10.172
www   IN  A           2.26.10.172
*     IN  A           2.26.10.172
