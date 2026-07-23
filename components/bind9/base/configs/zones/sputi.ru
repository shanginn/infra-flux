$TTL 300
@     IN  SOA ns1.shanginn.io. hostmaster.sputi.ru. (
  2026072301 ; serial
  3H         ; refresh
  1H         ; retry
  1W         ; expire
  5M )       ; minimum

@     IN  NS  ns1.shanginn.io.
@     IN  NS  ns2.shanginn.io.

@     IN  A   185.221.212.224
*     IN  A   185.221.212.224

@     IN  CAA 0 issue "letsencrypt.org"
@     IN  CAA 0 issuewild "letsencrypt.org"
