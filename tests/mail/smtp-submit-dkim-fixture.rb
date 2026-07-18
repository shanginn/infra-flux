#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "openssl"
require "socket"
require "time"

raise "set ALLOW_DKIM_FIXTURE=true" unless ENV["ALLOW_DKIM_FIXTURE"] == "true"

host = ENV.fetch("SMTP_HOST", "127.0.0.1")
raise "DKIM fixture is restricted to localhost" unless %w[127.0.0.1 ::1 localhost].include?(host)

port = Integer(ENV.fetch("SMTP_PORT"))
username = ENV.fetch("SMTP_USER")
password = ENV.fetch("SMTP_PASSWORD")

def response(socket)
  lines = []
  loop do
    line = socket.gets
    raise "SMTP connection closed unexpectedly" unless line

    lines << line
    break unless line[3] == "-"
  end
  Integer(lines.last[0, 3])
end

def command(socket, value)
  socket.write("#{value}\r\n")
  response(socket)
end

tcp = TCPSocket.new(host, port)
raise "invalid SMTP greeting" unless response(tcp) == 220
raise "EHLO failed" unless command(tcp, "EHLO test.example.net") == 250
raise "STARTTLS failed" unless command(tcp, "STARTTLS") == 220

context = OpenSSL::SSL::SSLContext.new
context.verify_mode = OpenSSL::SSL::VERIFY_NONE
socket = OpenSSL::SSL::SSLSocket.new(tcp, context)
socket.hostname = host if socket.respond_to?(:hostname=)
socket.sync_close = true
socket.connect

raise "EHLO after STARTTLS failed" unless command(socket, "EHLO test.example.net") == 250

encoded = Base64.strict_encode64("\0#{username}\0#{password}")
raise "SMTP AUTH failed" unless command(socket, "AUTH PLAIN #{encoded}") == 235
raise "declared alias sender rejected" unless command(socket, "MAIL FROM:<support@vibesites.ru>") == 250
raise "local recipient rejected" unless command(socket, "RCPT TO:<hello@vibesites.ru>") == 250
raise "SMTP DATA rejected" unless command(socket, "DATA") == 354

message = <<~MESSAGE.gsub("\n", "\r\n")
  From: Vibesites Support <support@vibesites.ru>
  To: hello@vibesites.ru
  Date: #{Time.now.utc.rfc2822}
  Message-ID: <dkim-fixture-20260717@vibesites.ru>
  Subject: DKIM alignment fixture

  Non-sensitive fixture used only for local DKIM validation.
MESSAGE

socket.write(message)
socket.write("\r\n.\r\n")
raise "SMTP message was not accepted" unless response(socket) == 250

command(socket, "QUIT")
puts "smtp-dkim-fixture accepted=1 sender=support@vibesites.ru recipient=local"
