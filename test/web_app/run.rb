#!/usr/bin/env ruby
# frozen_string_literal: true

# Web eID Test Server
#
# Simple HTTP server for Web eID testing that runs the Sinatra application
# for use with Cloudflare tunnel. The tunnel provides HTTPS termination.

require_relative "app"

puts "🚀 Starting Web eID Test Server"
puts "Running on: http://localhost:4567"
puts "Note: Use with Cloudflare tunnel for HTTPS access"
puts ""

# Run the Sinatra app on HTTP (tunnel will provide HTTPS)
WebEidTestApp.run!(
  port: 4567,
  bind: "0.0.0.0",
  environment: :development
)
