$TTL 24H
@     IN  SOA @       hostmaster.vibesites.ru. (
  5   ; serial
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
*.dns 300 IN  A       185.221.212.224

; Map 'www' and 'mail' subdomains to the same IP address
www   IN  A           185.221.212.224
mail  IN  A           185.221.212.224

; Set the IP address for the nameserver
ns1   IN  A           185.221.212.224

; Shared mail-hub records are intentionally held until the cutover checklist
; is complete. Remove the leading semicolons in one reviewed Git change only
; after PTR/FCrDNS, public TLS, off-site restore and external relay tests pass.
;
; @       300 IN MX  10 mx1.shanginn.io.
; @       300 IN TXT "v=spf1 ip4:185.221.212.224 -all"
; mail2026._domainkey 300 IN TXT (
;   "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkX0BfiZx/lcrgq3w1TQWQdW93XIRjJw98GylR/+6KlXKFPlX2+VsqsWcg0U/+y+/gYJhC5Kb6n3SXvYYLIqiS+KnVuniS1mK3sGkdZeiyyFe4cFvxg2odWsUK1pqQ35Tvy2FCNeB"
;   "gW6NrbDvyvytoRi8r5Sp3hWRbAlqsVerO+hswyopA6VOoVhKdISmcOZYOzLNmJdGVKD6sbNbGsNnK0HGixkw+8Hur0987ut785cXtLElwjsGvBK9PxCps2i8gvPuu7oqKcYylHiZwmH4jot3UsZHF1Q8r1oLh+pwAfSqGJR0UFcQ0AwBhEKA"
;   "Dj+n8vzV4/skmtjHq2okEyVw9wIDAQAB"
; )
; _dmarc  300 IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@vibesites.ru; adkim=s; aspf=s; fo=1; pct=100"
; autoconfig 300 IN CNAME mail.shanginn.io.
; autodiscover 300 IN CNAME mail.shanginn.io.
