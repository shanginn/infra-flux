#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "openssl"
require "socket"

host = ENV.fetch("SMTP_HOST", "127.0.0.1")
port = Integer(ENV.fetch("SMTP_PORT"))
mode = ENV.fetch("SMTP_MODE", "plain")
username = ENV["SMTP_USER"]
password = ENV["SMTP_PASSWORD"]
mail_from = ENV.fetch("SMTP_FROM")
rcpt_to = ENV["SMTP_RCPT"]
expected_mail = Integer(ENV.fetch("EXPECT_MAIL_CODE"))
expected_rcpt = ENV["EXPECT_RCPT_CODE"]&.to_i

def response(socket)
  lines = []
  loop do
    line = socket.gets
    raise "SMTP connection closed unexpectedly" unless line

    lines << line
    break unless line[3] == "-"
  end
  [Integer(lines.last[0, 3]), lines]
end

def command(socket, value)
  socket.write("#{value}\r\n")
  response(socket)
end

def expect!(actual, expected, stage)
  return if actual == expected

  raise "#{stage}: expected SMTP #{expected}, got #{actual}"
end

tcp = TCPSocket.new(host, port)
socket = tcp

if mode == "implicit"
  context = OpenSSL::SSL::SSLContext.new
  context.verify_mode = ENV["SMTP_INSECURE"] == "true" ? OpenSSL::SSL::VERIFY_NONE : OpenSSL::SSL::VERIFY_PEER
  socket = OpenSSL::SSL::SSLSocket.new(tcp, context)
  socket.hostname = host if socket.respond_to?(:hostname=)
  socket.sync_close = true
  socket.connect
end

banner, = response(socket)
expect!(banner, 220, "banner")

ehlo, = command(socket, "EHLO test.example.net")
expect!(ehlo, 250, "EHLO")

if mode == "starttls"
  starttls, = command(socket, "STARTTLS")
  expect!(starttls, 220, "STARTTLS")

  context = OpenSSL::SSL::SSLContext.new
  context.verify_mode = ENV["SMTP_INSECURE"] == "true" ? OpenSSL::SSL::VERIFY_NONE : OpenSSL::SSL::VERIFY_PEER
  tls_socket = OpenSSL::SSL::SSLSocket.new(tcp, context)
  tls_socket.hostname = host if tls_socket.respond_to?(:hostname=)
  tls_socket.sync_close = true
  tls_socket.connect
  socket = tls_socket

  ehlo, = command(socket, "EHLO test.example.net")
  expect!(ehlo, 250, "EHLO after STARTTLS")
end

auth_code = nil
if username || password
  raise "both SMTP_USER and SMTP_PASSWORD are required" unless username && password

  encoded = Base64.strict_encode64("\0#{username}\0#{password}")
  auth_code, = command(socket, "AUTH PLAIN #{encoded}")
  expect!(auth_code, 235, "AUTH")
end

mail_code, = command(socket, "MAIL FROM:<#{mail_from}>")
expect!(mail_code, expected_mail, "MAIL FROM")

rcpt_code = nil
if rcpt_to
  rcpt_code, = command(socket, "RCPT TO:<#{rcpt_to}>")
  expect!(rcpt_code, expected_rcpt, "RCPT TO")
end

command(socket, "RSET") if mail_code == 250
command(socket, "QUIT")

puts [
  "smtp-session-check",
  "mode=#{mode}",
  ("auth=#{auth_code}" if auth_code),
  "mail=#{mail_code}",
  ("rcpt=#{rcpt_code}" if rcpt_code)
].compact.join(" ")
