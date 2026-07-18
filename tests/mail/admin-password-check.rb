#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "openssl"
require "uri"
require "yaml"

document = YAML.safe_load($stdin.read, permitted_classes: [], permitted_symbols: [], aliases: false)
secret_data = document.fetch("data")
password = Base64.strict_decode64(secret_data.fetch("admin-password"))

endpoint = URI(ENV.fetch("MAIL_AUTH_URL", "https://mail-admin.shanginn.io/api/auth"))
request_body = {
  type: "authCode",
  accountName: "admin@mailhub.shanginn.io",
  accountSecret: password,
  mfaToken: nil,
  clientId: "stalwart-webui",
  redirectUri: "https://mail-admin.shanginn.io/admin/oauth/callback",
  nonce: nil,
  scope: nil,
  codeChallenge: nil,
  codeChallengeMethod: nil,
  state: nil
}

def authenticate(endpoint, request_body)
  request = Net::HTTP::Post.new(endpoint)
  request["Content-Type"] = "application/json"
  request.body = JSON.generate(request_body)
  http = Net::HTTP.new(endpoint.host, endpoint.port)
  http.use_ssl = endpoint.scheme == "https"
  http.open_timeout = 10
  http.read_timeout = 10
  if http.use_ssl?
    certificate_store = OpenSSL::X509::Store.new
    certificate_store.set_default_paths
    certificate_store.flags = 0
    http.cert_store = certificate_store
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  end
  response = http.start { |client| client.request(request) }
  abort("authentication endpoint returned HTTP #{response.code}") unless response.is_a?(Net::HTTPSuccess)
  JSON.parse(response.body)
end

result = authenticate(endpoint, request_body)
abort("admin password authentication failed: type=#{result["type"]}") unless result["type"] == "authenticated"

puts("admin password authentication passed")
