# Provider request: reverse DNS for Rubase

Send this exact request to the provider that controls reverse DNS for
`185.221.212.224`:

> Please set the IPv4 reverse DNS (PTR) record for `185.221.212.224` to
> `mx1.shanginn.io.` (fully-qualified hostname, trailing dot accepted).
> The forward A record `mx1.shanginn.io -> 185.221.212.224` is already managed
> by us. Please confirm when the PTR has propagated and that no older PTR
> remains for this address.

Acceptance:

```sh
dig +short mx1.shanginn.io A
# must be exactly 185.221.212.224

dig +short -x 185.221.212.224
# must be exactly mx1.shanginn.io.
```

Do not publish a production MX or enable the public mail Service before both
directions match.
