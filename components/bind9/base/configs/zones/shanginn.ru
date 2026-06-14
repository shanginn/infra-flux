$TTL 24H
@     IN  SOA @       hostmaster.shanginn.ru. (
  4   ; serial
  3H  ; refresh
  1H  ; retry
  1W  ; expire
  3H )    ; minimum

@     IN  MX  10      mail.shanginn.ru.

@     IN  NS          ns1.shanginn.ru.
@     IN  NS          ns2.shanginn.ru.

ns1   IN  A           185.221.212.224
ns2   IN  A           185.221.212.224
mail  IN  A           185.221.212.224

@     IN  A           185.199.108.153
@     IN  A           185.199.109.153
@     IN  A           185.199.110.153
@     IN  A           185.199.111.153
