#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "time"
require "yaml"

catalog_dir = ENV.fetch("CATALOG_DIR", "/catalog")
confirmation = ENV["CONFIRM_PRUNE"]
allow_mail_deletion = ENV["ALLOW_MAIL_DELETION"] == "true"
domain_id = ENV["PRUNE_DOMAIN_ID"]
abort("ALLOW_MAIL_DELETION=true is required") unless allow_mail_deletion
abort("CONFIRM_PRUNE is required") if confirmation.to_s.empty?
abort("PRUNE_DOMAIN_ID is required; query and review the exact Stalwart Domain id first") if domain_id.to_s.empty?

operations = []
Dir.glob(File.join(catalog_dir, "*.yaml")).sort.each do |path|
  data = YAML.safe_load(File.read(path), permitted_classes: [], permitted_symbols: [], aliases: false)
  domain = data.dig("metadata", "name")
  lifecycle = data.fetch("spec", {}).fetch("lifecycle", {})
  prune = lifecycle.fetch("prune", {})
  next unless lifecycle["state"] == "disabled" && prune["approved"] == true
  next unless prune["token"] == confirmation

  disabled_since = Time.iso8601(lifecycle.fetch("disabledSince"))
  abort("#{domain}: disabledSince must be at least 7 days old") if Time.now.utc - disabled_since < 7 * 86_400

  # This plan is intentionally never scheduled. The CLI executes destroy
  # operations in reverse, so Domain is listed before its Accounts/DKIM.
  operations << { "@type" => "destroy", "object" => "Domain", "value" => { "name" => domain } }
  operations << { "@type" => "destroy", "object" => "Account", "value" => { "domainId" => domain_id } }
  operations << { "@type" => "destroy", "object" => "DkimSignature", "value" => { "domainId" => domain_id } }
end

abort("no disabled domain matched the confirmation token") if operations.empty?
operations.each { |operation| puts(JSON.generate(operation)) }
