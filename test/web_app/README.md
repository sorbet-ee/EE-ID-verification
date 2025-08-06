# Web eID Test Application

A Sinatra web application for testing Estonian Web eID authentication with ID cards.

## Quick Start

From the main project directory:

```bash
# Via Makefile (recommended)
make webeid_test

# Or manually
cd test/web_app
./start.sh
```

## Features

- **Web eID Integration**: Test authentication with Estonian ID cards via browser
- **Secure HTTPS**: Uses Cloudflare tunnel for proper HTTPS required by Web eID  
- **Real Card Testing**: Authenticate with physical Estonian ID cards and card readers
- **Session Management**: Secure session handling with CSRF protection
- **Clean Interface**: Modern web interface with detailed status messages

## Requirements

1. **Estonian ID card** inserted in a card reader
2. **Web eID browser extension** installed and enabled
3. **Web eID native application** installed on your system
4. **Cloudflare tunnel** (`cloudflared`) for HTTPS

## Architecture

The Web eID test application uses the main `EE-ID-verification` gem for backend verification logic while providing a web interface for testing the complete Web eID authentication flow.

### Components

- `app.rb` - Main Sinatra application with API endpoints
- `run.rb` - HTTP server launcher
- `start.sh` - Application launcher script with tunnel setup
- `views/index.erb` - Single-page web interface
- `public/js/web-eid-lib.js` - Official Web eID JavaScript library

### API Endpoints

- `GET /` - Main application page
- `GET /api/csrf-token` - Get CSRF token for secure requests
- `GET /api/auth/challenge` - Get authentication challenge nonce
- `POST /api/auth/login` - Submit authentication token for verification
- `GET /api/user` - Get current authenticated user info  
- `POST /api/logout` - Clear user session

## Development

The web application is integrated with the main project's development workflow:

- Uses the main project's Gemfile for dependencies
- Requires the main gem for verification logic
- Shares the same development commands via Makefile

See the main project README for complete usage instructions.