#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "yaml"

CATALOG_DIR = ENV.fetch("CATALOG_DIR", "/catalog")
CREDENTIALS_DIR = ENV.fetch("CREDENTIALS_DIR", "/credentials")
PLAN_FILE = ENV.fetch("PLAN_FILE", "/work/plan.ndjson")
BACKUP_TARGETS_FILE = ENV.fetch("BACKUP_TARGETS_FILE", "/work/backup-targets.tsv")
SYSTEM_DOMAIN = ENV.fetch("SYSTEM_DOMAIN", "mailhub.shanginn.io")
BOOTSTRAP = ENV.fetch("BOOTSTRAP", "false") == "true"

def fail!(message)
  warn("mail catalog validation failed: #{message}")
  exit(1)
end

def slug(value)
  value.downcase.gsub(/[^a-z0-9]+/, "-").gsub(/\A-|-\z/, "")
end

def read_secret(name)
  fail!("credentialRef is empty") if name.to_s.empty?

  path = File.join(CREDENTIALS_DIR, name)
  fail!("missing encrypted credential #{name.inspect}") unless File.file?(path)

  value = File.read(path).strip
  fail!("encrypted credential #{name.inspect} is empty") if value.empty?
  value
end

def address(local_part, domain)
  "#{local_part}@#{domain}".downcase
end

def set(values)
  values.to_h { |value| [value, true] }
end

def list(values)
  values.each_with_index.to_h { |value, index| [index.to_s, value] }
end

documents = Dir.glob(File.join(CATALOG_DIR, "*.yaml")).sort.map do |path|
  data = YAML.safe_load(File.read(path), permitted_classes: [], permitted_symbols: [], aliases: false)
  fail!("#{path}: expected MailDomain") unless data.is_a?(Hash) &&
                                              data["apiVersion"] == "mail.shanginn.io/v1alpha1" &&
                                              data["kind"] == "MailDomain"
  [path, data]
end
fail!("no domain files found in #{CATALOG_DIR}") if documents.empty?

domains = {}
documents.each do |path, data|
  name = data.dig("metadata", "name").to_s.downcase
  fail!("#{path}: metadata.name must be an ASCII DNS name") unless name.match?(/\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z/)
  fail!("#{path}: duplicate domain #{name}") if domains.key?(name)
  domains[name] = data.fetch("spec", {})
end
fail!("catalog must not declare reserved system domain #{SYSTEM_DOMAIN}") if domains.key?(SYSTEM_DOMAIN)

max_recipients_per_message = domains.map do |domain, spec|
  routing = spec.fetch("routing", {})
  fail!("#{domain}: only routing.inbound=local is supported") unless routing.fetch("inbound", "local") == "local"
  fail!("#{domain}: only routing.outbound=direct is supported") unless routing.fetch("outbound", "direct") == "direct"
  policies = spec.fetch("policies", {})
  fail!("#{domain}: anonymous relay must remain disabled") if policies.fetch("anonymousRelayAllowed", false)
  fail!("#{domain}: bulk sending is not supported by this hub") if policies.fetch("bulkAllowed", false)
  policies.fetch("maxRecipientsPerMessage", 50)
end.min
fail!("policies.maxRecipientsPerMessage must be between 1 and 100") unless (1..100).cover?(max_recipients_per_message)

domain_refs = { SYSTEM_DOMAIN => "domain-#{slug(SYSTEM_DOMAIN)}" }
domains.each_key { |name| domain_refs[name] = "domain-#{slug(name)}" }

domain_values = {
  domain_refs.fetch(SYSTEM_DOMAIN) => {
    "name" => SYSTEM_DOMAIN,
    "description" => "Internal identities for the declarative mail hub",
    "aliases" => {},
    "isEnabled" => true,
    "allowRelaying" => false,
    "catchAllAddress" => nil,
    "subAddressing" => { "@type" => "Disabled" },
    "certificateManagement" => { "@type" => "Manual" },
    "dkimManagement" => { "@type" => "Manual" },
    "dnsManagement" => { "@type" => "Manual" },
    "reportAddressUri" => nil
  }
}

domains.each do |name, spec|
  lifecycle = spec.fetch("lifecycle", {})
  state = lifecycle.fetch("state", "active")
  fail!("#{name}: lifecycle.state must be active or disabled") unless %w[active disabled].include?(state)
  if lifecycle.dig("prune", "approved") && state != "disabled"
    fail!("#{name}: prune can only be approved after lifecycle.state=disabled")
  end

  catch_all = spec.fetch("catchAll", { "enabled" => false })
  catch_address = catch_all["enabled"] ? catch_all["address"].to_s.downcase : nil
  fail!("#{name}: catchAll.enabled requires catchAll.address") if catch_all["enabled"] && catch_address.empty?

  domain_values[domain_refs.fetch(name)] = {
    "name" => name,
    "description" => spec.fetch("description", "Git-managed mail domain #{name}"),
    "aliases" => set(spec.fetch("domainAliases", [])),
    "isEnabled" => state == "active",
    "allowRelaying" => false,
    "catchAllAddress" => catch_address,
    "subAddressing" => { "@type" => spec.fetch("subAddressing", true) ? "Enabled" : "Disabled" },
    "certificateManagement" => { "@type" => "Manual" },
    "dkimManagement" => { "@type" => "Manual" },
    "dnsManagement" => { "@type" => "Manual" },
    "reportAddressUri" => spec["reportAddress"] ? "mailto:#{spec.fetch("reportAddress")}" : nil
  }
end

groups = []
users = []
claimed_addresses = {}
backup_targets = []

domains.each do |domain, spec|
  defaults = spec.fetch("quotas", {})

  spec.fetch("groups", []).each do |group|
    local = group.fetch("localPart").downcase
    primary = address(local, domain)
    fail!("#{domain}: duplicate address #{primary}") if claimed_addresses.key?(primary)
    claimed_addresses[primary] = "group #{primary}"
    ref = "group-#{slug(primary)}"
    groups << [ref, domain, group]

    group.fetch("aliases", []).each do |entry|
      alias_domain = entry.fetch("domain", domain).downcase
      fail!("#{primary}: alias domain #{alias_domain} is not declared") unless domain_refs.key?(alias_domain)
      alias_address = address(entry.fetch("localPart"), alias_domain)
      fail!("#{domain}: duplicate address #{alias_address}") if claimed_addresses.key?(alias_address)
      claimed_addresses[alias_address] = "alias of #{primary}"
    end
  end

  spec.fetch("accounts", []).each do |account|
    local = account.fetch("localPart").downcase
    primary = address(local, domain)
    fail!("#{domain}: duplicate address #{primary}") if claimed_addresses.key?(primary)
    claimed_addresses[primary] = "mailbox #{primary}"
    ref = "account-#{slug(primary)}"
    users << [ref, domain, account, defaults]

    account.fetch("aliases", []).each do |entry|
      alias_domain = entry.fetch("domain", domain).downcase
      fail!("#{primary}: alias domain #{alias_domain} is not declared") unless domain_refs.key?(alias_domain)
      alias_address = address(entry.fetch("localPart"), alias_domain)
      fail!("#{domain}: duplicate address #{alias_address}") if claimed_addresses.key?(alias_address)
      claimed_addresses[alias_address] = "alias of #{primary}"
    end
  end
end

domains.each do |domain, spec|
  %w[postmaster abuse].each do |required|
    required_address = address(required, domain)
    fail!("#{domain}: required address #{required_address} is missing") unless claimed_addresses.key?(required_address)
  end

  catch_all = spec.fetch("catchAll", { "enabled" => false })
  if catch_all["enabled"] && !claimed_addresses.key?(catch_all.fetch("address").downcase)
    fail!("#{domain}: catch-all target #{catch_all.fetch("address")} is not a declared mailbox, group or alias")
  end
end

group_refs_by_address = groups.to_h do |ref, domain, group|
  [address(group.fetch("localPart"), domain), ref]
end

group_values = groups.to_h do |ref, domain, group|
  aliases = group.fetch("aliases", []).map do |entry|
    alias_domain = entry.fetch("domain", domain).downcase
    {
      "enabled" => true,
      "name" => entry.fetch("localPart").downcase,
      "domainId" => "##{domain_refs.fetch(alias_domain)}",
      "description" => entry.fetch("description", "Git-managed alias")
    }
  end
  [
    ref,
    {
      "@type" => "Group",
      "name" => group.fetch("localPart").downcase,
      "domainId" => "##{domain_refs.fetch(domain)}",
      "emailAddress" => address(group.fetch("localPart"), domain),
      "description" => group.fetch("description", "Git-managed group"),
      "aliases" => list(aliases),
      "roles" => { "@type" => "Default" },
      "permissions" => { "@type" => "Inherit" },
      "quotas" => {},
      "locale" => group.fetch("locale", "en_US"),
      "timeZone" => group["timeZone"]
    }
  ]
end

user_values = users.to_h do |ref, domain, account, defaults|
  primary = address(account.fetch("localPart"), domain)
  state = account.fetch("state", "active")
  fail!("#{primary}: state must be active or disabled") unless %w[active disabled].include?(state)

  aliases = account.fetch("aliases", []).map do |entry|
    alias_domain = entry.fetch("domain", domain).downcase
    {
      "enabled" => entry.fetch("enabled", true),
      "name" => entry.fetch("localPart").downcase,
      "domainId" => "##{domain_refs.fetch(alias_domain)}",
      "description" => entry.fetch("description", "Git-managed alias")
    }
  end

  allowed_identities = [primary] + account.fetch("aliases", []).map do |entry|
    address(entry.fetch("localPart"), entry.fetch("domain", domain))
  end
  account.fetch("senderIdentities", allowed_identities).each do |identity|
    fail!("#{primary}: sender identity #{identity} is not the mailbox or one of its aliases") unless allowed_identities.include?(identity.downcase)
  end

  credentials = if state == "active"
                  [{
                    "@type" => "Password",
                    "secret" => read_secret(account.fetch("credentialRef")),
                    "allowedIps" => set(account.fetch("allowedIps", [])),
                    "expiresAt" => nil,
                    "otpAuth" => nil
                  }]
                else
                  []
                end

  if state == "active" && account.dig("backup", "enabled")
    archive = "#{slug(primary)}.sqlite"
    backup_targets << [primary, account.fetch("credentialRef"), archive]
  end

  memberships = account.fetch("groups", []).map do |group_address|
    normalized = group_address.downcase
    fail!("#{primary}: unknown group #{normalized}") unless group_refs_by_address.key?(normalized)
    "##{group_refs_by_address.fetch(normalized)}"
  end

  quota = account.fetch("quotaBytes", defaults.fetch("defaultMailboxBytes", 5 * 1024 * 1024 * 1024))
  [
    ref,
    {
      "@type" => "User",
      "name" => account.fetch("localPart").downcase,
      "domainId" => "##{domain_refs.fetch(domain)}",
      "emailAddress" => primary,
      "description" => account.fetch("description", "Git-managed mailbox #{primary}"),
      "aliases" => list(aliases),
      "credentials" => list(credentials),
      "roles" => { "@type" => "User" },
      "permissions" => { "@type" => "Inherit" },
      "encryptionAtRest" => { "@type" => "Disabled" },
      "memberGroupIds" => set(memberships),
      "quotas" => { "maxDiskQuota" => quota },
      "locale" => account.fetch("locale", "en_US"),
      "timeZone" => account.fetch("timeZone", "Asia/Yekaterinburg")
    }
  ]
end

operations = []
operations << {
  "@type" => "upsert",
  "object" => "Domain",
  "matchOn" => ["name"],
  "value" => domain_values
}

if BOOTSTRAP
  operations << {
    "@type" => "upsert",
    "object" => "Role",
    "matchOn" => ["description"],
    "value" => {
      "role-gitops" => {
        "description" => "GitOps mail reconciler (no destroy permissions)",
        "roleIds" => {},
        "enabledPermissions" => set(%w[
          authenticate
          sysDomainGet sysDomainCreate sysDomainUpdate sysDomainQuery
          sysAccountGet sysAccountCreate sysAccountUpdate sysAccountQuery
          sysDkimSignatureGet sysDkimSignatureCreate sysDkimSignatureUpdate sysDkimSignatureQuery
          sysNetworkListenerGet sysNetworkListenerCreate sysNetworkListenerUpdate sysNetworkListenerQuery
          sysAllowedIpGet sysAllowedIpCreate sysAllowedIpUpdate sysAllowedIpQuery
          sysSystemSettingsGet sysSystemSettingsUpdate
          sysMetricsGet sysMetricsUpdate
          sysSecurityGet sysSecurityUpdate
          sysHttpGet sysHttpUpdate
          sysImapGet sysImapUpdate
          sysMtaInboundSessionGet sysMtaInboundSessionUpdate
          sysMtaStageAuthGet sysMtaStageAuthUpdate
          sysMtaStageMailGet sysMtaStageMailUpdate
          sysMtaStageRcptGet sysMtaStageRcptUpdate
          sysSenderAuthGet sysSenderAuthUpdate
        ]),
        "disabledPermissions" => set(%w[
          sysDomainDestroy sysAccountDestroy sysDkimSignatureDestroy
          sysNetworkListenerDestroy sysCertificateDestroy sysRoleDestroy
          sysAllowedIpDestroy
        ])
      }
    }
  }

  operations << {
    "@type" => "create",
    "object" => "Certificate",
    "value" => {
      "certificate-mail-hub" => {
        "certificate" => { "@type" => "File", "filePath" => "/run/tls/tls.crt" },
        "privateKey" => { "@type" => "File", "filePath" => "/run/tls/tls.key" }
      }
    }
  }

  operations << {
    "@type" => "upsert",
    "object" => "Account",
    "matchOn" => ["emailAddress"],
    "value" => {
      "account-gitops" => {
        "@type" => "User",
        "name" => "gitops",
        "domainId" => "##{domain_refs.fetch(SYSTEM_DOMAIN)}",
        "emailAddress" => "gitops@#{SYSTEM_DOMAIN}",
        "description" => "GitOps reconciler service account",
        "aliases" => {},
        "credentials" => list([{
          "@type" => "Password",
          "secret" => read_secret("gitops-password"),
          "allowedIps" => set(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]),
          "expiresAt" => nil,
          "otpAuth" => nil
        }]),
        "roles" => { "@type" => "Custom", "roleIds" => { "#role-gitops" => true } },
        "permissions" => { "@type" => "Inherit" },
        "encryptionAtRest" => { "@type" => "Disabled" },
        "memberGroupIds" => {},
        "quotas" => { "maxDiskQuota" => 0 },
        "locale" => "en_US",
        "timeZone" => "Asia/Yekaterinburg"
      },
      "account-admin" => {
        "@type" => "User",
        "name" => "admin",
        "domainId" => "##{domain_refs.fetch(SYSTEM_DOMAIN)}",
        "emailAddress" => "admin@#{SYSTEM_DOMAIN}",
        "description" => "Permanent human administrator; IP restricted",
        "aliases" => {},
        "credentials" => list([{
          "@type" => "Password",
          "secret" => read_secret("admin-password"),
          "allowedIps" => set(read_secret("admin-allowed-ips").split(",").map(&:strip)),
          "expiresAt" => nil,
          "otpAuth" => nil
        }]),
        "roles" => { "@type" => "Admin" },
        "permissions" => { "@type" => "Inherit" },
        "encryptionAtRest" => { "@type" => "Disabled" },
        "memberGroupIds" => {},
        "quotas" => { "maxDiskQuota" => 0 },
        "locale" => "en_US",
        "timeZone" => "Asia/Yekaterinburg"
      }
    }
  }
end

operations << {
  "@type" => "upsert",
  "object" => "Account",
  "matchOn" => ["emailAddress"],
  "value" => group_values
} unless group_values.empty?
operations << {
  "@type" => "upsert",
  "object" => "Account",
  "matchOn" => ["emailAddress"],
  "value" => user_values
} unless user_values.empty?

seen_selectors = {}
dkim_values = domains.to_h do |domain, spec|
  dkim = spec.fetch("dkim")
  selector = dkim.fetch("selector")
  fail!("#{domain}: DKIM selector #{selector} is already used by #{seen_selectors[selector]}") if seen_selectors.key?(selector)
  seen_selectors[selector] = domain
  [
    "dkim-#{slug(domain)}-#{slug(selector)}",
    {
      "@type" => "Dkim1RsaSha256",
      "domainId" => "##{domain_refs.fetch(domain)}",
      "selector" => selector,
      "privateKey" => {
        "@type" => "File",
        "filePath" => dkim.fetch("privateKeyFile", "/run/dkim/#{domain}.pem")
      },
      "canonicalization" => "relaxed/relaxed",
      "headers" => set(%w[Date From Message-ID Subject To]),
      "report" => true,
      "stage" => "active"
    }
  ]
end
operations << {
  "@type" => "upsert",
  "object" => "DkimSignature",
  "matchOn" => ["selector"],
  "value" => dkim_values
}

listener_values = {
  "listener-http" => {
    "name" => "http-internal",
    "bind" => set(["0.0.0.0:8080"]),
    "protocol" => "http",
    "useTls" => false,
    "tlsImplicit" => false,
    "maxConnections" => 1024
  },
  "listener-https-internal" => {
    "name" => "https-internal",
    "bind" => set(["0.0.0.0:8443"]),
    "protocol" => "http",
    "useTls" => true,
    "tlsImplicit" => true,
    "maxConnections" => 64
  },
  "listener-smtp" => {
    "name" => "smtp",
    "bind" => set(["0.0.0.0:25"]),
    "protocol" => "smtp",
    "useTls" => true,
    "tlsImplicit" => false,
    "maxConnections" => 1024
  },
  "listener-submission" => {
    "name" => "submission",
    "bind" => set(["0.0.0.0:587"]),
    "protocol" => "smtp",
    "useTls" => true,
    "tlsImplicit" => false,
    "maxConnections" => 512
  },
  "listener-submissions" => {
    "name" => "submissions",
    "bind" => set(["0.0.0.0:465"]),
    "protocol" => "smtp",
    "useTls" => true,
    "tlsImplicit" => true,
    "maxConnections" => 512
  },
  "listener-imaps" => {
    "name" => "imaps",
    "bind" => set(["0.0.0.0:993"]),
    "protocol" => "imap",
    "useTls" => true,
    "tlsImplicit" => true,
    "maxConnections" => 512
  }
}
operations << {
  "@type" => "upsert",
  "object" => "NetworkListener",
  "matchOn" => ["name"],
  "value" => listener_values
}

operations << {
  "@type" => "upsert",
  "object" => "AllowedIp",
  "matchOn" => ["address"],
  "value" => {
    "allowed-kubernetes-pods" => {
      "address" => "10.42.0.0/16",
      "reason" => "Git-managed Kubernetes pod network"
    },
    "allowed-kubernetes-services" => {
      "address" => "10.43.0.0/16",
      "reason" => "Git-managed Kubernetes service network"
    },
    "allowed-rubase-node" => {
      "address" => "185.221.212.224",
      "reason" => "Git-managed single Kubernetes node and kubelet probes"
    }
  }
}

system_settings = {
  "defaultDomainId" => "##{domain_refs.fetch(SYSTEM_DOMAIN)}",
  "defaultHostname" => "mx1.shanginn.io",
  "mailExchangers" => list([{ "hostname" => "mx1.shanginn.io", "priority" => 10 }]),
  "maxConnections" => 4096,
  # Rubase publishes mail L4 directly and Traefik does not send the binary
  # PROXY protocol. Stalwart v0.16.13 does not reliably remove a previously
  # persisted non-empty IpMask list when an empty list is applied, so retain a
  # non-routed TEST-NET range instead of trusting any real source network.
  "proxyTrustedNetworks" => set(["192.0.2.0/24"]),
  "services" => {
    "imap" => { "hostname" => "mail.shanginn.io", "cleartext" => false },
    "jmap" => { "hostname" => "mail.shanginn.io", "cleartext" => false },
    "smtp" => { "hostname" => "mail.shanginn.io", "cleartext" => false }
  }
}
operations << { "@type" => "update", "object" => "SystemSettings", "value" => system_settings }
operations << {
  "@type" => "update",
  "object" => "Metrics",
  "value" => {
    "metricsPolicy" => "exclude",
    "metrics" => {},
    "prometheus" => {
      "@type" => "Enabled",
      "authUsername" => "victoriametrics",
      "authSecret" => {
        "@type" => "EnvironmentVariable",
        "variableName" => "STALWART_METRICS_PASSWORD"
      }
    }
  }
}
operations << {
  "@type" => "update",
  "object" => "Security",
  "value" => {
    "authBanRate" => { "count" => 10, "period" => 900_000 },
    "authBanPeriod" => 3_600_000,
    "abuseBanRate" => { "count" => 20, "period" => 86_400_000 },
    "abuseBanPeriod" => 86_400_000,
    "loiterBanRate" => { "count" => 100, "period" => 86_400_000 },
    "loiterBanPeriod" => 21_600_000,
    "scanBanRate" => { "count" => 20, "period" => 86_400_000 },
    "scanBanPeriod" => 86_400_000
  }
}
operations << {
  "@type" => "update",
  "object" => "Http",
  "value" => {
    "enableHsts" => true,
    "rateLimitAnonymous" => { "count" => 100, "period" => 60_000 },
    "rateLimitAuthenticated" => { "count" => 1000, "period" => 60_000 },
    "usePermissiveCors" => false,
    "useXForwarded" => true
  }
}
operations << {
  "@type" => "update",
  "object" => "Imap",
  "value" => {
    "allowPlainTextAuth" => false,
    "maxAuthFailures" => 3,
    "maxConcurrent" => 8,
    "maxRequestRate" => { "count" => 2000, "period" => 60_000 }
  }
}
operations << {
  "@type" => "update",
  "object" => "MtaInboundSession",
  "value" => {
    "timeout" => { "else" => "5m" },
    "transferLimit" => { "else" => "262144000" },
    "maxDuration" => { "else" => "10m" }
  }
}
operations << {
  "@type" => "update",
  "object" => "MtaStageAuth",
  "value" => {
    "saslMechanisms" => {
      "match" => list([{ "if" => "listener != 'smtp' && is_tls", "then" => "[plain, login]" }]),
      "else" => "false"
    },
    "require" => {
      "match" => list([{ "if" => "listener != 'smtp'", "then" => "true" }]),
      "else" => "false"
    },
    "mustMatchSender" => { "else" => "true" },
    "maxFailures" => { "else" => "3" },
    "waitOnFail" => { "else" => "5s" }
  }
}
operations << {
  "@type" => "update",
  "object" => "MtaStageMail",
  "value" => {
    "isSenderAllowed" => { "else" => "true" },
    "rewrite" => { "else" => "false" },
    "script" => { "else" => "false" }
  }
}
operations << {
  "@type" => "update",
  "object" => "MtaStageRcpt",
  "value" => {
    "allowRelaying" => { "else" => "!is_empty(authenticated_as)" },
    "maxFailures" => { "else" => "5" },
    "maxRecipients" => { "else" => max_recipients_per_message.to_s },
    "waitOnFail" => { "else" => "5s" }
  }
}
operations << {
  "@type" => "update",
  "object" => "SenderAuth",
  "value" => {
    "arcVerify" => {
      "match" => list([{ "if" => "listener == 'smtp'", "then" => "relaxed" }]),
      "else" => "disable"
    },
    "dkimSignDomain" => {
      "match" => list([{
        "if" => "is_local_domain(sender_domain) && !is_empty(authenticated_as)",
        "then" => "sender_domain"
      }]),
      "else" => "false"
    },
    "dkimStrict" => true,
    "dkimVerify" => {
      "match" => list([{ "if" => "listener == 'smtp'", "then" => "relaxed" }]),
      "else" => "disable"
    },
    "dmarcVerify" => {
      "match" => list([{ "if" => "listener == 'smtp'", "then" => "relaxed" }]),
      "else" => "disable"
    },
    "reverseIpVerify" => {
      "match" => list([{ "if" => "listener == 'smtp'", "then" => "relaxed" }]),
      "else" => "disable"
    },
    "spfEhloVerify" => {
      "match" => list([{ "if" => "listener == 'smtp'", "then" => "relaxed" }]),
      "else" => "disable"
    },
    "spfFromVerify" => {
      "match" => list([{ "if" => "listener == 'smtp'", "then" => "relaxed" }]),
      "else" => "disable"
    }
  }
}

File.open(PLAN_FILE, "w", 0o600) do |file|
  operations.each { |operation| file.puts(JSON.generate(operation)) }
end
File.open(BACKUP_TARGETS_FILE, "w", 0o600) do |file|
  backup_targets.each { |target| file.puts(target.join("\t")) }
end

warn("rendered #{operations.length} safe operations for #{domains.length} public domain(s); bootstrap=#{BOOTSTRAP}; destroy=0")
