#!/usr/bin/env ruby
# frozen_string_literal: true

require "openssl"
require "socket"

host = ENV.fetch("IMAP_HOST", "127.0.0.1")
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

tcp = TCPSocket.new(host, port)
context = OpenSSL::SSL::SSLContext.new
context.verify_mode = ENV["IMAP_INSECURE"] == "true" ? OpenSSL::SSL::VERIFY_NONE : OpenSSL::SSL::VERIFY_PEER
socket = OpenSSL::SSL::SSLSocket.new(tcp, context)
socket.hostname = host if socket.respond_to?(:hostname=)
socket.sync_close = true
socket.connect

greeting = socket.gets
raise "invalid IMAP greeting" unless greeting&.start_with?("* OK")

socket.write("a1 LOGIN #{quote_imap(username)} #{quote_imap(password)}\r\n")
login = tagged_response(socket, "a1")
raise "IMAP LOGIN failed with #{login}" unless login == "OK"

socket.write("a2 STATUS INBOX (MESSAGES)\r\n")
status = tagged_response(socket, "a2")
raise "IMAP STATUS failed with #{status}" unless status == "OK"

socket.write("a3 LOGOUT\r\n")
logout = tagged_response(socket, "a3")
raise "IMAP LOGOUT failed with #{logout}" unless logout == "OK"

puts "imap-session-check tls=ok login=#{login} status=#{status}"
