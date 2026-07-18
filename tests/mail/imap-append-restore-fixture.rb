#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "openssl"
require "socket"
require "time"

raise "set ALLOW_RESTORE_FIXTURE=true" unless ENV["ALLOW_RESTORE_FIXTURE"] == "true"

host = ENV.fetch("IMAP_HOST", "127.0.0.1")
raise "restore fixture is restricted to localhost" unless %w[127.0.0.1 ::1 localhost].include?(host)

port = Integer(ENV.fetch("IMAP_PORT"))
username = ENV.fetch("IMAP_USER")
password = ENV.fetch("IMAP_PASSWORD")

def quote_imap(value)
  %("#{value.gsub(/["\\]/) { |character| "\\#{character}" }}")
end

def tagged_response(socket, tag)
  loop do
    line = socket.gets
    raise "IMAP connection closed unexpectedly" unless line

    next unless line.start_with?("#{tag} ")

    return line.split(/\s+/, 3)[1]
  end
end

attachment = Base64.strict_encode64("mail-hub-restore-fixture\n")
message = <<~MESSAGE.gsub("\n", "\r\n")
  From: Mail Restore Fixture <hello@vibesites.ru>
  To: hello@vibesites.ru
  Date: #{Time.now.utc.rfc2822}
  Message-ID: <restore-fixture-20260717@vibesites.ru>
  Subject: Mail hub isolated restore fixture
  MIME-Version: 1.0
  Content-Type: multipart/mixed; boundary="restore-fixture-boundary"

  --restore-fixture-boundary
  Content-Type: text/plain; charset=utf-8

  Non-sensitive fixture used only for the isolated backup and restore rehearsal.
  --restore-fixture-boundary
  Content-Type: text/plain; name="restore-fixture.txt"
  Content-Disposition: attachment; filename="restore-fixture.txt"
  Content-Transfer-Encoding: base64

  #{attachment}
  --restore-fixture-boundary--
MESSAGE

tcp = TCPSocket.new(host, port)
context = OpenSSL::SSL::SSLContext.new
context.verify_mode = OpenSSL::SSL::VERIFY_NONE
socket = OpenSSL::SSL::SSLSocket.new(tcp, context)
socket.hostname = host if socket.respond_to?(:hostname=)
socket.sync_close = true
socket.connect

raise "invalid IMAP greeting" unless socket.gets&.start_with?("* OK")

socket.write("a1 LOGIN #{quote_imap(username)} #{quote_imap(password)}\r\n")
raise "IMAP LOGIN failed" unless tagged_response(socket, "a1") == "OK"

socket.write("a2 APPEND INBOX {#{message.bytesize}}\r\n")
continuation = socket.gets
raise "IMAP APPEND continuation missing" unless continuation&.start_with?("+")

socket.write(message)
socket.write("\r\n")
raise "IMAP APPEND failed" unless tagged_response(socket, "a2") == "OK"

socket.write("a3 LOGOUT\r\n")
tagged_response(socket, "a3")

puts "imap-restore-fixture appended=1 attachment=1"
