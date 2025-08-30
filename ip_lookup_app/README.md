# IP Lookup Tool

A modern, beautiful Flask web application for looking up IP address information using the ipinfo.io API with curl.

## Features

- 🌍 **IP Address Lookup**: Get detailed information about any IP address
- 🎨 **Modern UI**: Beautiful gradient design with animations
- 📱 **Responsive**: Works perfectly on desktop and mobile devices
- ⚡ **Fast**: Uses curl for quick API requests
- 🔍 **Comprehensive Info**: Shows location, ISP, timezone, and more

## Information Provided

- IP Address
- City and Region
- Country
- Geographic Coordinates
- Organization/ISP
- Postal Code
- Timezone

## Prerequisites

- Python 3.6 or higher
- Flask
- curl (usually pre-installed on most systems)

## Installation

1. **Clone or download the project files**

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```

4. **Open your browser** and go to:
   ```
   http://localhost:5000
   ```

## Usage

1. Enter any valid IPv4 address in the input field
2. Click the "Lookup" button or press Enter
3. View the detailed information about the IP address

## Example IP Addresses to Test

- `8.8.8.8` (Google DNS)
- `1.1.1.1` (Cloudflare DNS)
- `208.67.222.222` (OpenDNS)

## File Structure

```
ip_lookup_app/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── templates/
│   └── index.html     # Main HTML template
├── static/
│   └── style.css      # CSS styling
└── # Secora IP Lookup & URL Shortener

A modern web application for IP intelligence gathering and URL shortening with OAuth authentication.

## Features

- **IP Intelligence**: Comprehensive IP lookup with security analysis
- **URL Shortener**: Multi-service URL shortening platform  
- **OAuth Authentication**: Secure login with Google and Microsoft accounts
- **Activity Tracking**: Complete history of user activities
- **Modern UI**: Dark theme with responsive design

## Authentication Setup

This application uses OAuth for authentication. You'll need to set up OAuth applications with Google and Microsoft.

### Google OAuth Setup

1. Go to [Google Cloud Console](https://console.developers.google.com/)
2. Create a new project or select existing one
3. Enable the Google+ API
4. Create OAuth 2.0 credentials:
   - Application type: Web application
   - Authorized redirect URIs: `http://localhost:5000/auth/google/callback`
5. Copy the Client ID and Client Secret

### Microsoft OAuth Setup

1. Go to [Azure Portal](https://portal.azure.com/)
2. Navigate to "App registrations"
3. Create a new registration:
   - Name: Secora App
   - Supported account types: Accounts in any organizational directory and personal Microsoft accounts
   - Redirect URI: `http://localhost:5000/auth/microsoft/callback`
4. Copy the Application (client) ID
5. Create a client secret in "Certificates & secrets"

### Environment Variables

Set these environment variables before running the app:

```bash
export SECRET_KEY="your-secret-key-here"
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export MICROSOFT_CLIENT_ID="your-microsoft-client-id"
export MICROSOFT_CLIENT_SECRET="your-microsoft-client-secret"
```

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up OAuth credentials (see above)

3. Run the application:
```bash
python app.py
```

4. Visit `http://localhost:5000`

## Usage

1. Click "Sign In" and choose Google or Microsoft
2. Use IP Intelligence to analyze IP addresses
3. Use URL Shortener to create short links
4. View your activity history in your profile

## Security Features

- OAuth 2.0 authentication (no passwords stored)
- Rate limiting on all endpoints
- Input sanitization and validation
- CSRF protection
- Secure headers implementation          # This file
```

## Technologies Used

- **Backend**: Flask (Python)
- **Frontend**: HTML5, CSS3, JavaScript
- **Styling**: Bootstrap 5, Font Awesome
- **API**: ipinfo.io (via curl)

## API Credits

This application uses the [ipinfo.io](https://ipinfo.io) service for IP geolocation data.

## License

This project is open source and available under the MIT License.

# Secora - Security Intelligence Platform

A comprehensive IP lookup and security analysis tool that checks IPs against 23+ different sources for VPN/proxy/Tor detection and threat intelligence.

## Features

- **Multi-Source IP Lookup**: Combines data from 23+ APIs and databases
- **VPN/Proxy Detection**: Advanced detection using multiple sources
- **Tor Network Detection**: Specialized Tor exit node identification
- **Abuse Database Integration**: AbuseIPDB, VirusTotal, CleanTalk integration
- **Security Intelligence**: Comprehensive threat analysis
- **Rate Limiting**: Built-in protection against abuse
- **Modern UI**: Clean, responsive design with Tailwind CSS

## API Sources & Rate Limits

### Geographic & Network Intelligence
- **ipinfo.io**: 50,000/month free tier
- **ip-api.com**: 1,000/month free (45 requests/minute)
- **ipgeolocation.io**: 1,000/month free
- **ipapi.co**: 1,000/month free
- **ipstack.com**: 1,000/month free
- **ipwhois.io**: 10,000/month free
- **freeipapi.com**: Unlimited free

### VPN/Proxy Detection
- **proxycheck.io**: 1,000/day free
- **getipintel.net**: 500/day free
- **vpnapi.io**: 1,000/month free
- **ipqualityscore.com**: 5,000/month free
- **scamalytics.com**: Free web scraping (limited)
- **blacklist.de**: Free queries (rate limited)
- **ip2proxy.com**: 500/month free

### Tor Detection
- **Tor Project**: Official exit node list (unlimited)
- **dan.me.uk**: Free Tor list (unlimited)
- **iphunter.info**: Free Tor detection
- **stopforumspam.com**: Free API (unlimited)
- **ipthreat.net**: Free queries

### Security & Abuse Intelligence  
- **AbuseIPDB**: 1,000/day free tier ⭐ NEW
- **VirusTotal**: 4 requests/minute free
- **CleanTalk**: Free web queries
- **ThreatCrowd**: Free API (rate limited)

### Rate Limiting (Built-in)
- **/my-ip**: 5 requests/minute per IP
- **/lookup**: 20 requests/minute per IP

## Security Features

- Input validation and sanitization
- XSS protection with HTML escaping
- SSRF protection (blocks private IPs)
- Content-Type validation
- Security headers (CSP, X-Frame-Options)
- **Port scanning removed** for security compliance

## Installation

```bash
pip install -r requirements.txt
python app.py
```

## Usage

1. Visit the web interface
2. Click "Test My IP" to check your current IP
3. Or enter any public IP address for analysis
4. View comprehensive security intelligence results

## API Integration Notes

- Most APIs work without keys but have stricter limits
- For production use, consider getting API keys for higher limits
- Some sources use web scraping (legal but rate-limited)
- Concurrent execution with 23 workers for fast results 