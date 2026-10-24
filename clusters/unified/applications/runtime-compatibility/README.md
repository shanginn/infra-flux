# Runtime compatibility

The `temporal` namespace contains a DNS alias only. Generach's deployed bot
still hardcodes `temporal-frontend.temporal:7233`; the ExternalName resolves it
to the single server in `temporal-system`. There is no second server or database.
Keep the alias until all deployed clients actually honor their configured address.

The shared Telegram Bot API server requires its native Telegram connection.
Its otherwise isolated Pods may reach only the observed datacenter address
`149.154.167.51:5222`. Additional datacenter endpoints need actual connection
evidence and a scoped rule; this policy does not grant general Internet access.
