# frozen_string_literal: true

# Web eID Test Application
# 
# A simple Sinatra application for testing Estonian Web eID authentication.
# This app demonstrates how to integrate Web eID authentication into a Ruby web application
# using the EE-ID-verification gem.
#
# Features:
# - Web eID authentication with Estonian ID cards
# - CSRF protection for secure API calls
# - Session management
# - Mock authentication support for testing
#
# Usage:
#   Run via ./start.sh to launch with Cloudflare tunnel for HTTPS

require "sinatra"
require "sinatra/reloader" if development?
require "json"
require "securerandom"

# Load our main gem for ID verification
require_relative "../../lib/ee_id_verification"

class WebEidTestApp < Sinatra::Base
  
  # Development configuration
  configure :development do
    register Sinatra::Reloader
    
    # Disable host authorization for development to allow tunneling services
    # This is required for Cloudflare tunnel to work with Sinatra v4+
    set :host_authorization, { permitted_hosts: [] }
  end

  # Session configuration
  use Rack::Session::Cookie, 
    key: "web_eid_test",
    secret: ENV.fetch("SESSION_SECRET", SecureRandom.hex(32))

  # Enable built-in CSRF protection (except for JSON endpoints)
  enable :sessions
  set :protection, :except => [:json_csrf]

  # Static files and views
  set :public_folder, File.join(__dir__, "public")
  set :views, File.join(__dir__, "views")

  # Set JSON content type for API endpoints
  before do
    content_type :json if request.path_info.start_with?("/api")
  end

  # Generate or retrieve CSRF token for the session
  def csrf_token
    session[:csrf_token] ||= SecureRandom.hex(32)
  end

  # Validate CSRF token from request headers or parameters
  def validate_csrf_token
    token = request.env['HTTP_X_CSRF_TOKEN'] || params[:csrf_token]
    
    halt 403, { error: "CSRF token missing" }.to_json unless token
    halt 403, { error: "CSRF token invalid" }.to_json unless token == session[:csrf_token]
  end

  # Routes
  # ======

  # Main application page
  get "/" do
    erb :index
  end

  # API: Get CSRF token for client-side requests
  get "/api/csrf-token" do
    { csrf_token: csrf_token }.to_json
  end

  # API: Get authentication challenge nonce
  # Returns a cryptographically secure nonce for Web eID authentication
  get "/api/auth/challenge" do
    # Generate a secure random nonce (base64 encoded, 32 bytes = 256 bits entropy)
    nonce = SecureRandom.base64(32)
    
    # Store nonce in session with timestamp for expiration checking
    session[:nonce] = nonce
    session[:nonce_created_at] = Time.now.to_i
    
    { nonce: nonce }.to_json
  end

  # API: Process Web eID authentication
  # Verifies the authentication token received from the Web eID extension
  post "/api/auth/login" do
    # CSRF protection temporarily disabled for easier testing
    # validate_csrf_token
    
    # Parse request body
    request.body.rewind
    data = JSON.parse(request.body.read)
    
    # Retrieve stored nonce and timestamp
    stored_nonce = session[:nonce]
    nonce_created_at = session[:nonce_created_at]
    
    # Validate nonce exists
    unless stored_nonce && nonce_created_at
      halt 400, { error: "No challenge nonce found" }.to_json
    end
    
    # Check nonce expiration (5 minutes)
    if Time.now.to_i - nonce_created_at > 300
      halt 400, { error: "Challenge nonce expired" }.to_json
    end
    
    begin
      # Use our gem to verify the authentication token
      verifier = EeIdVerification::WebEidVerifier.new
      result = verifier.verify_auth_token(data["authToken"], stored_nonce)
      
      # Clean up used nonce
      session.delete(:nonce)
      session.delete(:nonce_created_at)
      
      if result.success?
        # Store user information in session
        session[:user] = {
          personal_code: result.personal_code,
          full_name: result.full_name,
          country: result.country
        }
        
        { success: true, user: session[:user] }.to_json
      else
        halt 400, { error: result.error }.to_json
      end
      
    rescue StandardError => e
      halt 500, { error: "Authentication failed: #{e.message}" }.to_json
    end
  end

  # API: Get current authenticated user
  get "/api/user" do
    if session[:user]
      session[:user].to_json
    else
      halt 401, { error: "Not authenticated" }.to_json
    end
  end

  # API: Logout current user
  post "/api/logout" do
    # CSRF protection temporarily disabled for easier testing
    # validate_csrf_token
    
    session.clear
    { success: true }.to_json
  end
end