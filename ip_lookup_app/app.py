from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests
import json
import re
import concurrent.futures
import time
import html
import bcrypt
import os
from functools import wraps
from collections import defaultdict, deque
from datetime import datetime, timedelta
import ipaddress
import threading
from flask_socketio import SocketIO, emit, join_room

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///ip_lookup.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
socketio = SocketIO(app)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def set_password(self, password):
        """Hash and set password"""
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def __repr__(self):
        return f'<User {self.username}>'

class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv4 or IPv6 (null for URL shortening)
    search_type = db.Column(db.String(20), default='ip_lookup')  # 'ip_lookup' or 'url_shorten'
    url_shortened = db.Column(db.Text, nullable=True)  # For URL shortening history
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('searches', lazy=True))

class IPReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_type = db.Column(db.String(50), nullable=False)  # 'malicious', 'spam', 'suspicious', etc.
    comment = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('reports', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception as e:
        # If there's a schema error, return None to log out the user
        print(f"User loading error (schema mismatch): {e}")
        return None

# Rate limiting storage (in production, use Redis or database)
rate_limit_storage = defaultdict(lambda: deque())

def rate_limit(max_requests=10, window_seconds=60):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client IP
            client_ip = get_client_ip()
            current_time = time.time()
            
            # Clean old requests
            requests_for_ip = rate_limit_storage[client_ip]
            while requests_for_ip and current_time - requests_for_ip[0] > window_seconds:
                requests_for_ip.popleft()
            
            # Check rate limit
            if len(requests_for_ip) >= max_requests:
                return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
            
            # Add current request
            requests_for_ip.append(current_time)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_client_ip():
    """Safely get client IP address"""
    # Check for forwarded headers (but validate them)
    forwarded_ips = request.environ.get('HTTP_X_FORWARDED_FOR', '')
    if forwarded_ips:
        # Take the first IP, but validate it
        first_ip = forwarded_ips.split(',')[0].strip()
        if is_valid_ip(first_ip):
            return first_ip
    
    # Fallback to remote addr
    remote_addr = request.environ.get('REMOTE_ADDR', '127.0.0.1')
    return remote_addr if is_valid_ip(remote_addr) else '127.0.0.1'

@app.after_request
def after_request(response):
    """Add security headers"""
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; "
        "font-src 'self' cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    
    # Other security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Remove server information
    response.headers.pop('Server', None)
    
    return response

def sanitize_string(value, max_length=500):
    """Sanitize and validate string input"""
    if not isinstance(value, str):
        return ''
    
    # HTML escape and truncate
    sanitized = html.escape(value.strip())[:max_length]
    
    # Remove any potentially dangerous characters
    sanitized = re.sub(r'[<>"\']', '', sanitized)
    
    return sanitized

def is_valid_ip(ip):
    """Validate IP address format with additional security checks"""
    if not ip or not isinstance(ip, str):
        return False
    
    # Basic length check
    if len(ip) > 15 or len(ip) < 7:
        return False
    
    # Check for valid IPv4 format
    ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    if not ip_pattern.match(ip):
        return False
    
    # Block private/reserved IP ranges for external lookups
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    try:
        octets = [int(part) for part in parts]
    except ValueError:
        return False
    
    # Check for private/reserved ranges
    if (octets[0] == 10 or 
        (octets[0] == 172 and 16 <= octets[1] <= 31) or
        (octets[0] == 192 and octets[1] == 168) or
        octets[0] == 127 or  # localhost
        octets[0] == 0 or    # invalid
        octets[0] >= 224):   # multicast/reserved
        return False
    
    return True

def lookup_ipinfo(ip_address):
    """Lookup IP information using ipinfo.io"""
    try:
        response = requests.get(f'https://ipinfo.io/{ip_address}/json', timeout=5)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception:
        return None

def lookup_ipapi(ip_address):
    """Lookup IP information using ip-api.com"""
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                # Convert to ipinfo format
                return {
                    'ip': data.get('query'),
                    'city': data.get('city'),
                    'region': data.get('regionName'),
                    'country': data.get('country'),
                    'loc': f"{data.get('lat', '')},{data.get('lon', '')}" if data.get('lat') and data.get('lon') else None,
                    'org': data.get('org') or data.get('isp'),
                    'postal': data.get('zip'),
                    'timezone': data.get('timezone'),
                    'vpn_detected': data.get('proxy', False) or data.get('hosting', False),
                    'source': 'ip-api.com'
                }
        return None
    except Exception:
        return None

def lookup_ipgeolocation(ip_address):
    """Lookup IP information using ipgeolocation.io (free tier)"""
    try:
        # Using free tier (no API key required but limited requests)
        response = requests.get(f'https://api.ipgeolocation.io/ipgeo?ip={ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'ip': data.get('ip'),
                'city': data.get('city'),
                'region': data.get('state_prov'),
                'country': data.get('country_name'),
                'loc': f"{data.get('latitude', '')},{data.get('longitude', '')}" if data.get('latitude') and data.get('longitude') else None,
                'org': data.get('isp'),
                'postal': data.get('zipcode'),
                'timezone': data.get('time_zone', {}).get('name'),
                'source': 'ipgeolocation.io'
            }
        return None
    except Exception:
        return None

def lookup_proxycheck(ip_address):
    """Check VPN/Proxy using proxycheck.io (free tier - 100 queries/day)"""
    try:
        response = requests.get(f'http://proxycheck.io/v2/{ip_address}?key=&vpn=1&asn=1', timeout=5)
        if response.status_code == 200:
            data = response.json()
            ip_data = data.get(ip_address, {})
            if isinstance(ip_data, dict):
                return {
                    'ip': ip_address,
                    'country': ip_data.get('country'),
                    'city': ip_data.get('city'),
                    'region': ip_data.get('region'),
                    'org': ip_data.get('organisation'),
                    'vpn_detected': ip_data.get('proxy') == 'yes' or ip_data.get('type') in ['VPN', 'TOR'],
                    'proxy_type': ip_data.get('type', 'Unknown'),
                    'source': 'proxycheck.io'
                }
        return None
    except Exception:
        return None

def lookup_getipintel(ip_address):
    """Check proxy using getipintel.net (free API)"""
    try:
        # Free API with contact email parameter
        response = requests.get(f'http://check.getipintel.net/check.php?ip={ip_address}&contact=admin@example.com&format=json', timeout=5)
        if response.status_code == 200:
            data = response.json()
            # getipintel returns a probability score (0-1)
            probability = float(data.get('result', 0))
            return {
                'ip': ip_address,
                'vpn_detected': probability > 0.99,  # Much higher threshold to reduce false positives
                'vpn_probability': probability,
                'source': 'getipintel.net'
            }
        return None
    except Exception:
        return None

def lookup_vpnapi(ip_address):
    """Check VPN using vpnapi.io (free tier - 1000 requests/month)"""
    try:
        response = requests.get(f'https://vpnapi.io/api/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            security = data.get('security', {})
            location = data.get('location', {})
            network = data.get('network', {})
            
            return {
                'ip': ip_address,
                'city': location.get('city'),
                'region': location.get('region'),
                'country': location.get('country'),
                'org': network.get('autonomous_system_organization'),
                'vpn_detected': security.get('vpn', False) or security.get('proxy', False) or security.get('tor', False),
                'is_tor': security.get('tor', False),
                'is_proxy': security.get('proxy', False),
                'is_vpn': security.get('vpn', False),
                'source': 'vpnapi.io'
            }
        return None
    except Exception:
        return None

def lookup_ipqualityscore(ip_address):
    """Check IP using IPQualityScore (free checks available)"""
    try:
        response = requests.get(f'https://ipqualityscore.com/api/json/ip/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'vpn_detected': data.get('vpn', False),
                'proxy_detected': data.get('proxy', False),
                'tor_detected': data.get('tor', False),
                'fraud_score': data.get('fraud_score', 0)
            }
        return None
    except Exception:
        return None

def get_vpn_provider_info(ip_address):
    """Get VPN provider information from multiple sources"""
    vpn_providers = []
    
    # Source 1: VPN IP Database (free API)
    try:
        response = requests.get(f'https://vpnapi.io/api/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('security', {}).get('vpn'):
                provider = data.get('security', {}).get('name', 'Unknown VPN')
                vpn_providers.append({
                    'name': provider,
                    'confidence': 'high',
                    'source': 'vpnapi.io'
                })
    except Exception:
        pass
    
    # Source 2: IPHub (free tier)
    try:
        response = requests.get(f'http://v2.api.iphub.info/guest/ip/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('block') == 1:  # VPN/Proxy detected
                asn = data.get('asn', '')
                if asn:
                    # Common VPN ASN patterns
                    vpn_asns = {
                        'AS16509': 'Amazon AWS',
                        'AS14618': 'Amazon AWS',
                        'AS15169': 'Google Cloud',
                        'AS396982': 'Google Cloud',
                        'AS8075': 'Microsoft Azure',
                        'AS8075': 'Microsoft Azure',
                        'AS16276': 'OVH',
                        'AS16276': 'OVH',
                        'AS14061': 'DigitalOcean',
                        'AS14061': 'DigitalOcean',
                        'AS20473': 'Choopa',
                        'AS20473': 'Choopa',
                        'AS36351': 'Cloudflare',
                        'AS13335': 'Cloudflare',
                        'AS45102': 'Alibaba Cloud',
                        'AS45102': 'Alibaba Cloud',
                        'AS16509': 'Amazon AWS',
                        'AS14618': 'Amazon AWS',
                        'AS15169': 'Google Cloud',
                        'AS396982': 'Google Cloud',
                        'AS8075': 'Microsoft Azure',
                        'AS8075': 'Microsoft Azure',
                        'AS16276': 'OVH',
                        'AS16276': 'OVH',
                        'AS14061': 'DigitalOcean',
                        'AS14061': 'DigitalOcean',
                        'AS20473': 'Choopa',
                        'AS20473': 'Choopa',
                        'AS36351': 'Cloudflare',
                        'AS13335': 'Cloudflare',
                        'AS45102': 'Alibaba Cloud',
                        'AS45102': 'Alibaba Cloud'
                    }
                    if asn in vpn_asns:
                        vpn_providers.append({
                            'name': vpn_asns[asn],
                            'confidence': 'medium',
                            'source': 'iphub.info'
                        })
    except Exception:
        pass
    
    # Source 3: Manual VPN provider detection based on organization names
    try:
        # Get basic IP info to check organization
        ipinfo_response = requests.get(f'https://ipinfo.io/{ip_address}/json', timeout=5)
        if ipinfo_response.status_code == 200:
            ipinfo_data = ipinfo_response.json()
            org = ipinfo_data.get('org', '').lower()
            
            # Common VPN provider patterns
            vpn_patterns = {
                'nordvpn': 'NordVPN',
                'expressvpn': 'ExpressVPN',
                'surfshark': 'Surfshark',
                'cyberghost': 'CyberGhost',
                'protonvpn': 'ProtonVPN',
                'private internet access': 'Private Internet Access',
                'pia': 'Private Internet Access',
                'tunnelbear': 'TunnelBear',
                'windscribe': 'Windscribe',
                'mullvad': 'Mullvad',
                'ivpn': 'IVPN',
                'perfect privacy': 'Perfect Privacy',
                'airvpn': 'AirVPN',
                'hide.me': 'Hide.me',
                'vpn.ac': 'VPN.ac',
                'ovpn': 'OVPN',
                'azirevpn': 'AzireVPN',
                'cactusvpn': 'CactusVPN',
                'fastestvpn': 'FastestVPN',
                'ipvanish': 'IPVanish',
                'purevpn': 'PureVPN',
                'vyprvpn': 'VyprVPN',
                'hotspot shield': 'Hotspot Shield',
                'hoxx': 'Hoxx',
                'zenmate': 'ZenMate',
                'torguard': 'TorGuard',
                'vpn unlimited': 'VPN Unlimited',
                'safervpn': 'SaferVPN',
                'hide my ass': 'Hide My Ass',
                'hma': 'Hide My Ass',
                'buffered': 'Buffered VPN',
                'vpn.ht': 'VPN.ht',
                'liquidvpn': 'LiquidVPN',
                'blackvpn': 'BlackVPN',
                'vpnsecure': 'VPNSecure',
                'vpnarea': 'VPNArea',
                'vpnbaron': 'VPNBaron',
                'vpnjack': 'VPNJack',
                'vpnland': 'VPNLand',
                'vpnme': 'VPNMe',
                'vpnshazam': 'VPNShazam',
                'vpntunnel': 'VPNTunnel',
                'vpnunlimited': 'VPNUnlimited',
                'vpn.ac': 'VPN.ac',
                'vpnsecure': 'VPNSecure',
                'vpnarea': 'VPNArea',
                'vpnbaron': 'VPNBaron',
                'vpnjack': 'VPNJack',
                'vpnland': 'VPNLand',
                'vpnme': 'VPNMe',
                'vpnshazam': 'VPNShazam',
                'vpntunnel': 'VPNTunnel',
                'vpnunlimited': 'VPNUnlimited'
            }
            
            for pattern, provider in vpn_patterns.items():
                if pattern in org:
                    vpn_providers.append({
                        'name': provider,
                        'confidence': 'high',
                        'source': 'organization analysis'
                    })
                    break
    except Exception:
        pass
    
    return vpn_providers

def check_vpn_proxy(ip_address):
    """Check if IP is VPN/Proxy using multiple methods"""
    vpn_detected = False
    proxy_detected = False
    tor_detected = False
    vpn_sources = []
    tor_sources = []
    detection_count = 0
    sources_used = 0
    
    # Run multiple VPN/Proxy detection methods concurrently
    detection_methods = [
        lookup_proxycheck,
        lookup_getipintel,
        lookup_vpnapi,
        lookup_ipqualityscore,
        lookup_scamalytics,
        lookup_blacklist_de,
        lookup_ip2proxy,
        lookup_threatcrowd,
        lookup_ipstack,
        lookup_freeipapi
    ]
    
    # Run detection methods concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(method, ip_address): method.__name__ for method in detection_methods}
        
        for future in concurrent.futures.as_completed(futures, timeout=15):
            try:
                result = future.result()
                sources_used += 1
                
                if result:
                    if result.get('vpn_detected') or result.get('is_vpn'):
                        vpn_detected = True
                        detection_count += 1
                        source_name = futures[future]
                        if source_name not in vpn_sources:
                            vpn_sources.append(source_name)
                    
                    if result.get('proxy_detected') or result.get('is_proxy'):
                        proxy_detected = True
                        detection_count += 1
                        source_name = futures[future]
                        if source_name not in vpn_sources:
                            vpn_sources.append(source_name)
                    
                    if result.get('tor_detected') or result.get('is_tor'):
                        tor_detected = True
                        source_name = futures[future]
                        if source_name not in tor_sources:
                            tor_sources.append(source_name)
                            
            except Exception:
                continue
    
    # Check for Tor exit nodes
    tor_methods = [
        lookup_tor_exit_nodes,
        lookup_dan_me_tor,
        lookup_iphunter_tor,
        lookup_stopforumspam_tor,
        lookup_ipthreat_tor,
        lookup_tor_project_official,
        lookup_torflix_tor,
        lookup_nordvpn_tor,
        lookup_blutmagie_tor,
        lookup_onionoo_tor,
        lookup_tor_eff,
        lookup_tor_bulk_exit
    ]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(method, ip_address): method.__name__ for method in tor_methods}
        
        for future in concurrent.futures.as_completed(futures, timeout=15):
            try:
                result = future.result()
                sources_used += 1
                
                if result and (result.get('tor_detected') or result.get('is_tor')):
                    tor_detected = True
                    source_name = futures[future]
                    if source_name not in tor_sources:
                        tor_sources.append(source_name)
                        
            except Exception:
                continue
    
    # Check if it's a known legitimate service
    org_info = ""
    try:
        ipinfo_response = requests.get(f'https://ipinfo.io/{ip_address}/json', timeout=5)
        if ipinfo_response.status_code == 200:
            ipinfo_data = ipinfo_response.json()
            org_info = ipinfo_data.get('org', '')
    except Exception:
        pass
    
    is_legitimate = is_known_legitimate_service(ip_address, org_info)
    
    # Determine confidence level
    if tor_detected:
        detection_confidence = 'High' if len(tor_sources) > 1 else 'Medium'
    elif vpn_detected or proxy_detected:
        if detection_count >= 4:
            detection_confidence = 'High'
        elif detection_count >= 2:
            detection_confidence = 'Medium'
        else:
            detection_confidence = 'Low'
    else:
        detection_confidence = 'Clean'
    
    return {
        'vpn_detected': vpn_detected,
        'proxy_detected': proxy_detected,
        'tor_detected': tor_detected,
        'vpn_sources': vpn_sources,
        'tor_sources': tor_sources,
        'detection_count': detection_count,
        'tor_detection_count': len(tor_sources),
        'sources_used': sources_used,
        'is_legitimate_service': is_legitimate,
        'detection_confidence': detection_confidence
    }

def is_known_legitimate_service(ip_address, org_info):
    """Check if IP belongs to known legitimate services to reduce false positives"""
    legitimate_indicators = [
        # Major CDNs and cloud providers
        'cloudflare', 'amazon', 'google', 'microsoft', 'akamai', 
        'fastly', 'cdn', 'aws', 'azure', 'gcp', 'facebook',
        # Major ISPs
        'comcast', 'verizon', 'at&t', 'charter', 'cox',
        # Public DNS providers
        'quad9', 'opendns', 'level3'
    ]
    
    # Check common legitimate IP ranges
    legitimate_ips = [
        '1.1.1.1', '1.0.0.1',  # Cloudflare DNS
        '8.8.8.8', '8.8.4.4',  # Google DNS
        '9.9.9.9', '149.112.112.112',  # Quad9 DNS
    ]
    
    if ip_address in legitimate_ips:
        return True
    
    if org_info:
        org_lower = str(org_info).lower()
        for indicator in legitimate_indicators:
            if indicator in org_lower:
                return True
    
    return False

def lookup_ip(ip_address):
    """Main IP lookup function that combines multiple sources"""
    try:
        # Get basic IP information
        ipinfo_data = lookup_ipinfo(ip_address)
        ipapi_data = lookup_ipapi(ip_address)
        
        # Use the best available data
        if ipinfo_data:
            result = {
                'ip': ip_address,
                'city': ipinfo_data.get('city'),
                'region': ipinfo_data.get('region'),
                'country': ipinfo_data.get('country'),
                'loc': ipinfo_data.get('loc'),
                'org': ipinfo_data.get('org'),
                'postal': ipinfo_data.get('postal'),
                'timezone': ipinfo_data.get('timezone'),
                'asn': ipinfo_data.get('asn') or (ipinfo_data.get('org').split()[0] if ipinfo_data.get('org') and ipinfo_data.get('org').startswith('AS') else None)
            }
        elif ipapi_data:
            result = {
                'ip': ip_address,
                'city': ipapi_data.get('city'),
                'region': ipapi_data.get('regionName'),
                'country': ipapi_data.get('country'),
                'loc': f"{ipapi_data.get('lat')},{ipapi_data.get('lon')}" if ipapi_data.get('lat') and ipapi_data.get('lon') else None,
                'org': ipapi_data.get('org'),
                'postal': ipapi_data.get('zip'),
                'timezone': ipapi_data.get('timezone'),
                'asn': ipapi_data.get('as') or (ipapi_data.get('org').split()[0] if ipapi_data.get('org') and ipapi_data.get('org').startswith('AS') else None)
            }
        else:
            result = {'ip': ip_address}
        
        # Check VPN/Proxy status
        vpn_proxy_result = check_vpn_proxy(ip_address)
        if vpn_proxy_result and isinstance(vpn_proxy_result, dict):
            result.update(vpn_proxy_result)
        
        # Get VPN provider information
        vpn_providers = get_vpn_provider_info(ip_address)
        if vpn_providers:
            result['vpn_providers'] = vpn_providers
            # Set the most likely provider as the primary one
            high_confidence = [p for p in vpn_providers if p['confidence'] == 'high']
            if high_confidence:
                result['likely_vpn_provider'] = high_confidence[0]['name']
            else:
                result['likely_vpn_provider'] = vpn_providers[0]['name']
        
        # AbuseIPDB integration
        abuseipdb_data = lookup_abuseipdb(ip_address)
        result.update(abuseipdb_data)
        # Optionally, get the confidence score
        abuseipdb_conf = lookup_abuseipdb_confidence(ip_address)
        if abuseipdb_conf is not None:
            result['abuseipdb_confidence_score'] = abuseipdb_conf
        
        # Apple/NordVPN detection
        try:
            provider = check_apple_nordvpn(ip_address)
            if provider:
                result['likely_vpn_provider'] = provider
        except Exception:
            pass
        
        return result
        
    except Exception as e:
        print(f"Error in lookup_ip: {e}")
        return {'ip': ip_address, 'error': 'Lookup failed'}

@app.route('/')
def index():
    """Main page with IP lookup form"""
    lookups_today = 0
    if current_user.is_authenticated:
        from datetime import datetime
        today = datetime.utcnow().date()
        lookups_today = SearchHistory.query.filter(
            SearchHistory.user_id == current_user.id,
            SearchHistory.search_type == 'ip_lookup',
            db.func.date(SearchHistory.timestamp) == today
        ).count()
        print(f"User {current_user.id} lookups today: {lookups_today}")
    return render_template('index.html', lookups_today=lookups_today)

@app.route('/my-ip', methods=['GET'])
@rate_limit(max_requests=5, window_seconds=60)  # Limit to 5 requests per minute
def get_my_ip():
    """Get the client's actual public IP address"""
    try:
        # First try to get from request headers (for deployed apps)
        client_ip = get_client_ip()
        
        # If it's a private/localhost IP, use external service
        if client_ip in ['127.0.0.1', 'localhost'] or not is_valid_ip(client_ip):
            # Use external service to get real public IP
            ip_services = [
                'https://api.ipify.org?format=json',
                'https://httpbin.org/ip',
                'https://ipinfo.io/json'
            ]
            
            for service in ip_services:
                try:
                    headers = {
                        'User-Agent': 'Secora-Intelligence-Platform/1.0',
                        'Accept': 'application/json'
                    }
                    response = requests.get(service, timeout=5, headers=headers, verify=True)
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        # Different services return IP in different formats
                        user_ip = None
                        if 'ip' in data:
                            user_ip = sanitize_string(str(data['ip']))
                        elif 'origin' in data:  # httpbin format
                            user_ip = sanitize_string(str(data['origin']))
                        
                        # Validate the IP
                        if user_ip and is_valid_ip(user_ip):
                            return jsonify({
                                'success': True,
                                'ip': user_ip,
                                'service': sanitize_string(service)
                            })
                            
                except (requests.RequestException, json.JSONDecodeError, KeyError):
                    continue
            
            # If all external services fail, return error
            return jsonify({'error': 'Could not determine your public IP address'}), 400
        else:
            # Use the client IP from headers if it's valid
            return jsonify({
                'success': True,
                'ip': client_ip
            })
        
    except Exception as e:
        app.logger.error(f"Error getting client IP: {str(e)}")
        return jsonify({'error': 'Could not determine your IP address'}), 500

@app.route('/lookup', methods=['POST'])
@rate_limit(max_requests=20, window_seconds=60)  # Limit to 20 lookups per minute
def lookup():
    """Handle IP lookup requests"""
    try:
        # Validate content type
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        # Validate and sanitize input
        ip_address = data.get('ip_address', '')
        if not isinstance(ip_address, str):
            return jsonify({'error': 'IP address must be a string'}), 400
        
        ip_address = sanitize_string(ip_address.strip())
        
        if not ip_address:
            return jsonify({'error': 'Please enter an IP address'}), 400
        
        if not is_valid_ip(ip_address):
            return jsonify({'error': 'Please enter a valid public IP address'}), 400
        
        # Perform the lookup
        result = lookup_ip(ip_address)
        
        # Log activity if user is authenticated
        if current_user.is_authenticated:
            try:
                search_record = SearchHistory(
                    user_id=current_user.id,
                    ip_address=ip_address,
                    search_type='ip_lookup'
                )
                db.session.add(search_record)
                db.session.commit()
                from datetime import datetime
                today = datetime.utcnow().date()
                lookups_today = SearchHistory.query.filter(
                    SearchHistory.user_id == current_user.id,
                    SearchHistory.search_type == 'ip_lookup',
                    db.func.date(SearchHistory.timestamp) == today
                ).count()
                result['lookups_today'] = lookups_today
                # Emit WebSocket update
                socketio.emit(
                    'lookup_count_update',
                    {'lookups_today': lookups_today},
                    room=f'user_{current_user.id}'
                )
            except Exception as log_error:
                app.logger.error(f"Failed to log search: {log_error}")
                db.session.rollback()
        
        import json
        print("DEBUG: Returning to frontend:", json.dumps(result, indent=2))
        return jsonify(result)
        
    except Exception as e:
        # Log the error (in production, use proper logging)
        app.logger.error(f"Lookup error: {str(e)}")
        return jsonify({'error': 'An internal error occurred'}), 500

@app.route('/report-ip', methods=['POST'])
@login_required
@rate_limit(max_requests=5, window_seconds=60)  # Limit to 5 reports per minute
def report_ip():
    """Handle IP reporting requests"""
    try:
        # Validate content type
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        # Validate and sanitize input
        ip_address = data.get('ip_address', '')
        report_type = data.get('report_type', '')
        comment = data.get('comment', '')
        
        if not isinstance(ip_address, str) or not isinstance(report_type, str) or not isinstance(comment, str):
            return jsonify({'error': 'All fields must be strings'}), 400
        
        ip_address = sanitize_string(ip_address.strip())
        report_type = sanitize_string(report_type.strip())
        comment = sanitize_string(comment.strip(), max_length=1000)
        
        if not ip_address:
            return jsonify({'error': 'Please enter an IP address'}), 400
        
        if not is_valid_ip(ip_address):
            return jsonify({'error': 'Please enter a valid public IP address'}), 400
        
        if not report_type:
            return jsonify({'error': 'Please select a report type'}), 400
        
        if not comment:
            return jsonify({'error': 'Please provide a comment'}), 400
        
        # Check if user already reported this IP recently (within 24 hours)
        yesterday = datetime.utcnow() - timedelta(days=1)
        existing_report = IPReport.query.filter_by(
            user_id=current_user.id,
            ip_address=ip_address
        ).filter(IPReport.timestamp > yesterday).first()
        
        if existing_report:
            return jsonify({'error': 'You have already reported this IP address recently'}), 400
        
        # Create the report
        report = IPReport(
            user_id=current_user.id,
            ip_address=ip_address,
            report_type=report_type,
            comment=comment
        )
        
        db.session.add(report)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'IP address reported successfully'
        })
        
    except Exception as e:
        app.logger.error(f"Report error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'An internal error occurred'}), 500

@app.route('/get-ip-reports/<ip_address>', methods=['GET'])
def get_ip_reports(ip_address):
    """Get reports for a specific IP address"""
    try:
        if not is_valid_ip(ip_address):
            return jsonify({'error': 'Invalid IP address'}), 400
        
        # Get all reports for this IP (limit to recent ones for performance)
        reports = IPReport.query.filter_by(ip_address=ip_address)\
                               .order_by(IPReport.timestamp.desc())\
                               .limit(10).all()
        
        reports_data = []
        for report in reports:
            reports_data.append({
                'id': report.id,
                'report_type': report.report_type,
                'comment': report.comment,
                'timestamp': report.timestamp.isoformat(),
                'username': report.user.username
            })
        
        return jsonify({
            'success': True,
            'reports': reports_data,
            'total_reports': len(reports_data)
        })
        
    except Exception as e:
        app.logger.error(f"Get reports error: {str(e)}")
        return jsonify({'error': 'An internal error occurred'}), 500

def lookup_scamalytics(ip_address):
    """Check IP using Scamalytics (free checks available)"""
    try:
        # Scamalytics has a simple check endpoint
        response = requests.get(f'https://scamalytics.com/ip/{ip_address}', timeout=5)
        if response.status_code == 200:
            # Simple text parsing for basic detection
            content = response.text.lower()
            is_vpn = 'vpn' in content or 'proxy' in content or 'anonymizer' in content
            return {
                'ip': ip_address,
                'vpn_detected': is_vpn,
                'source': 'scamalytics.com'
            }
        return None
    except Exception:
        return None

def lookup_blacklist_de(ip_address):
    """Check IP using blacklist.de"""
    try:
        response = requests.get(f'http://www.blacklist.de/query_ip.php?ip={ip_address}', timeout=5)
        if response.status_code == 200:
            # Returns "found" if IP is in blacklist
            is_blacklisted = 'found' in response.text.lower()
            return {
                'ip': ip_address,
                'vpn_detected': is_blacklisted,
                'source': 'blacklist.de'
            }
        return None
    except Exception:
        return None

def lookup_ip2proxy(ip_address):
    """Check IP using IP2Proxy Web Service (free tier)"""
    try:
        # IP2Proxy lite database check
        response = requests.get(f'https://api.ip2proxy.com/?ip={ip_address}&format=json&package=PX1', timeout=5)
        if response.status_code == 200:
            data = response.json()
            # PX1 package checks for proxy
            is_proxy = data.get('isProxy', 'NO') == 'YES'
            return {
                'ip': ip_address,
                'vpn_detected': is_proxy,
                'proxy_type': data.get('proxyType', 'Unknown'),
                'country': data.get('countryName'),
                'source': 'ip2proxy.com'
            }
        return None
    except Exception:
        return None

def lookup_threatcrowd(ip_address):
    """Check IP using ThreatCrowd (free threat intelligence)"""
    try:
        response = requests.get(f'https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            # Check if IP has malicious indicators
            malware_count = len(data.get('hashes', []))
            domains_count = len(data.get('resolutions', []))
            # High activity might indicate VPN/proxy usage
            is_suspicious = malware_count > 0 or domains_count > 10
            return {
                'ip': ip_address,
                'vpn_detected': is_suspicious,
                'malware_count': malware_count,
                'domains_count': domains_count,
                'source': 'threatcrowd.org'
            }
        return None
    except Exception:
        return None

def lookup_ipapi_co(ip_address):
    """Check IP using ipapi.co (different from ip-api.com)"""
    try:
        response = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=5)
        if response.status_code == 200:
            data = response.json()
            # Check org field for VPN indicators
            org = data.get('org', '').lower()
            is_vpn = any(keyword in org for keyword in ['vpn', 'proxy', 'hosting', 'cloud', 'datacenter'])
            return {
                'ip': ip_address,
                'city': data.get('city'),
                'region': data.get('region'),
                'country': data.get('country_name'),
                'org': data.get('org'),
                'vpn_detected': is_vpn,
                'source': 'ipapi.co'
            }
        return None
    except Exception:
        return None

def lookup_ipstack(ip_address):
    """Check IP using IPStack (free tier available)"""
    try:
        # Using free tier without API key (limited features)
        response = requests.get(f'http://api.ipstack.com/{ip_address}?access_key=demo', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if not data.get('error'):
                return {
                    'ip': ip_address,
                    'city': data.get('city'),
                    'region': data.get('region_name'),
                    'country': data.get('country_name'),
                    'source': 'ipstack.com'
                }
        return None
    except Exception:
        return None

def lookup_ipwhois(ip_address):
    """Check IP using ipwhois.app (free API)"""
    try:
        response = requests.get(f'http://ipwhois.app/json/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                # Check org and ISP for VPN indicators
                org = data.get('org', '').lower()
                isp = data.get('isp', '').lower()
                is_vpn = any(keyword in f"{org} {isp}" for keyword in ['vpn', 'proxy', 'hosting', 'datacenter', 'cloud'])
                return {
                    'ip': ip_address,
                    'city': data.get('city'),
                    'region': data.get('region'),
                    'country': data.get('country'),
                    'org': data.get('org'),
                    'isp': data.get('isp'),
                    'vpn_detected': is_vpn,
                    'source': 'ipwhois.app'
                }
        return None
    except Exception:
        return None

def lookup_freeipapi(ip_address):
    """Check IP using freeipapi.com"""
    try:
        response = requests.get(f'https://freeipapi.com/api/json/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            # Check for VPN/proxy indicators in ISP field
            isp = data.get('isp', '').lower()
            is_vpn = any(keyword in isp for keyword in ['vpn', 'proxy', 'hosting', 'cloud', 'datacenter'])
            return {
                'ip': ip_address,
                'city': data.get('cityName'),
                'region': data.get('regionName'),
                'country': data.get('countryName'),
                'isp': data.get('isp'),
                'vpn_detected': is_vpn,
                'source': 'freeipapi.com'
            }
        return None
    except Exception:
        return None

def lookup_tor_exit_nodes(ip_address):
    """Check against Tor Project's official exit node list"""
    try:
        # Official Tor exit node list
        response = requests.get('https://check.torproject.org/torbulkexitlist', timeout=10)
        if response.status_code == 200:
            exit_nodes = response.text.strip().split('\n')
            is_tor_exit = ip_address in exit_nodes
            return {
                'ip': ip_address,
                'vpn_detected': is_tor_exit,
                'is_tor': is_tor_exit,
                'tor_type': 'exit_node' if is_tor_exit else None,
                'source': 'torproject.org'
            }
        return None
    except Exception:
        return None

def lookup_dan_me_tor(ip_address):
    """Check Tor using dan.me.uk Tor detector"""
    try:
        # Dan.me.uk provides a simple Tor check API
        response = requests.get(f'https://www.dan.me.uk/torcheck?ip={ip_address}', timeout=5)
        if response.status_code == 200:
            # Returns "Y" for Tor, "N" for not Tor
            is_tor = response.text.strip().upper() == 'Y'
            return {
                'ip': ip_address,
                'vpn_detected': is_tor,
                'is_tor': is_tor,
                'source': 'dan.me.uk'
            }
        return None
    except Exception:
        return None

def lookup_iphunter_tor(ip_address):
    """Check Tor using IP Hunter database"""
    try:
        response = requests.get(f'https://www.iphunter.info/api/v1/ip/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            is_tor = data.get('is_tor', False)
            is_proxy = data.get('is_proxy', False)
            return {
                'ip': ip_address,
                'vpn_detected': is_tor or is_proxy,
                'is_tor': is_tor,
                'is_proxy': is_proxy,
                'source': 'iphunter.info'
            }
        return None
    except Exception:
        return None

def lookup_stopforumspam_tor(ip_address):
    """Check using StopForumSpam database (tracks Tor)"""
    try:
        response = requests.get(f'http://www.stopforumspam.com/api?ip={ip_address}&json', timeout=5)
        if response.status_code == 200:
            data = response.json()
            appears = data.get('ip', {}).get('appears', 0)
            # High appearances often indicate Tor/proxy usage
            is_suspicious = appears > 0
            return {
                'ip': ip_address,
                'vpn_detected': is_suspicious,
                'spam_reports': appears,
                'source': 'stopforumspam.com'
            }
        return None
    except Exception:
        return None

def lookup_ipthreat_tor(ip_address):
    """Check using IP Threat database"""
    try:
        response = requests.get(f'https://api.ipthreat.net/v1/check/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            is_tor = data.get('is_tor', False)
            is_proxy = data.get('is_proxy', False)
            threat_level = data.get('threat_level', 0)
            return {
                'ip': ip_address,
                'vpn_detected': is_tor or is_proxy or threat_level > 3,
                'is_tor': is_tor,
                'is_proxy': is_proxy,
                'threat_level': threat_level,
                'source': 'ipthreat.net'
            }
        return None
    except Exception:
        return None

def lookup_tor_project_official(ip_address):
    """Check against official Tor project exit list"""
    try:
        # Official Tor project exit list
        response = requests.get('https://check.torproject.org/torbulkexitlist', timeout=10)
        if response.status_code == 200:
            tor_ips = response.text.strip().splitlines()
            if ip_address in tor_ips:
                return {
                    'ip': ip_address,
                    'is_tor': True,
                    'vpn_detected': True,
                    'source': 'torproject.org'
                }
        return None
    except Exception:
        return None

def lookup_torflix_tor(ip_address):
    """Check using TorFlix Tor detection"""
    try:
        response = requests.get(f'https://torflix.org/api/ip/{ip_address}', timeout=8)
        if response.status_code == 200:
            data = response.json()
            is_tor = data.get('tor', False) or data.get('is_tor', False)
            if is_tor:
                return {
                    'ip': ip_address,
                    'is_tor': True,
                    'vpn_detected': True,
                    'source': 'torflix.org'
                }
        return None
    except Exception:
        return None

def lookup_nordvpn_tor(ip_address):
    """Check using NordVPN's Tor detection API"""
    try:
        response = requests.get(f'https://nordvpn.com/wp-admin/admin-ajax.php?action=get_user_info_data&ip={ip_address}', timeout=8)
        if response.status_code == 200:
            data = response.json()
            if data.get('tor_detected') or 'tor' in str(data).lower():
                return {
                    'ip': ip_address,
                    'is_tor': True,
                    'vpn_detected': True,
                    'source': 'nordvpn.com'
                }
        return None
    except Exception:
        return None

def lookup_cymru_tor(ip_address):
    """Check using Team Cymru's Tor exit list"""
    try:
        # Team Cymru provides Tor exit node data
        response = requests.get('https://www.team-cymru.org/Services/ip-to-asn.html', timeout=8)
        # This would require parsing their data format, simplified for now
        # In production, you'd implement proper parsing of their feed
        return None
    except Exception:
        return None

def lookup_blutmagie_tor(ip_address):
    """Check using Blutmagie Tor exit list"""
    try:
        response = requests.get('https://torstatus.blutmagie.de/query_exit.php/Tor_ip_list_EXIT.csv', timeout=10)
        if response.status_code == 200:
            content = response.text
            # Parse CSV format exit list
            lines = content.strip().split('\n')
            for line in lines[1:]:  # Skip header
                if ip_address in line:
                    return {
                        'ip': ip_address,
                        'is_tor': True,
                        'vpn_detected': True,
                        'source': 'blutmagie.de'
                    }
        return None
    except Exception:
        return None

def lookup_onionoo_tor(ip_address):
    """Check using Tor Onionoo protocol"""
    try:
        # Onionoo is the protocol used by Tor Metrics
        response = requests.get(f'https://onionoo.torproject.org/details?search={ip_address}', timeout=10)
        if response.status_code == 200:
            data = response.json()
            relays = data.get('relays', [])
            if relays:
                for relay in relays:
                    if ip_address in relay.get('or_addresses', []) or ip_address in relay.get('exit_addresses', []):
                        return {
                            'ip': ip_address,
                            'is_tor': True,
                            'vpn_detected': True,
                            'relay_type': 'exit' if relay.get('exit_probability', 0) > 0 else 'relay',
                            'source': 'onionoo.torproject.org'
                        }
        return None
    except Exception:
        return None

def lookup_tor_eff(ip_address):
    """Check using EFF's Tor detection"""
    try:
        # EFF sometimes maintains Tor lists
        response = requests.get('https://atlas.torproject.org/api/search?type=relay&running=true', timeout=10)
        if response.status_code == 200:
            data = response.json()
            results = data.get('results', [])
            for result in results:
                if ip_address in str(result.get('addresses', [])):
                    return {
                        'ip': ip_address,
                        'is_tor': True,
                        'vpn_detected': True,
                        'source': 'atlas.torproject.org'
                    }
        return None
    except Exception:
        return None

def lookup_tor_bulk_exit(ip_address):
    """Check using Tor bulk exit list from multiple mirrors"""
    try:
        # Try multiple Tor exit list sources
        exit_lists = [
            'https://www.dan.me.uk/torlist/',
            'https://torstatus.rueckgr.at/ip_list_exit.php/Tor_ip_list_EXIT.csv',
            'https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1'
        ]
        
        for url in exit_lists:
            try:
                response = requests.get(url, timeout=8)
                if response.status_code == 200:
                    content = response.text
                    if ip_address in content:
                        return {
                            'ip': ip_address,
                            'is_tor': True,
                            'vpn_detected': True,
                            'source': f'tor_bulk_exit_list'
                        }
            except:
                continue
        return None
    except Exception:
        return None

def check_known_tor_ranges(ip_address):
    """Check against known Tor IP ranges and patterns - DISABLED due to false positives"""
    # This function was giving false positives for legitimate services like:
    # 1.1.1.1 (Cloudflare DNS), 8.8.8.8 (Google DNS), etc.
    # Better to rely on actual Tor exit node lists rather than IP range guessing
    return False, []

ABUSEIPDB_API_KEY = "b01b5f8d329c52490b1d5209801aeb768c0b55e5499be7f354fae3d31a1a8dd89d3d7d34ed09eeb7"

def lookup_abuseipdb(ip_address, max_age_days=90, per_page=5):
    url = "https://api.abuseipdb.com/api/v2/reports"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": max_age_days,
        "perPage": 6,
        "page": 1
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=8)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuseipdb_total_reports": data.get("total", 0),
                "abuseipdb_reports": data.get("results", []),
                "abuseipdb_last_page": data.get("lastPage", 1),
                "abuseipdb_error": None
            }
        else:
            return {"abuseipdb_error": f"Status {response.status_code}"}
    except Exception as e:
        return {"abuseipdb_error": str(e)}

# Optionally, get the confidence score from the /check endpoint

def lookup_abuseipdb_confidence(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=8)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return data.get("abuseConfidenceScore", None)
        else:
            return None
    except Exception:
        return None

def lookup_cleantalk(ip_address):
    """Check IP using CleanTalk (spam/abuse database)"""
    try:
        response = requests.get(f'https://cleantalk.org/blacklists/{ip_address}', timeout=5)
        if response.status_code == 200:
            content = response.text.lower()
            # Check for blacklist indicators
            is_blacklisted = any(keyword in content for keyword in 
                               ['blacklisted', 'spam', 'abuse', 'proxy', 'vpn'])
            return {
                'ip': ip_address,
                'vpn_detected': is_blacklisted,
                'source': 'cleantalk.org'
            }
        return None
    except Exception:
        return None

def lookup_virustotal_community(ip_address):
    """Check IP using VirusTotal community (without API key)"""
    try:
        # VirusTotal has a simple check page we can scrape
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(f'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=public&ip={ip_address}', 
                              headers=headers, timeout=5)
        
        # For free access, we'll do basic detection
        if response.status_code == 200:
            try:
                data = response.json()
                # Look for malicious detections
                detected_urls = data.get('detected_urls', [])
                detected_samples = data.get('detected_samples', [])
                
                # High activity might indicate compromised/VPN IP
                is_suspicious = len(detected_urls) > 5 or len(detected_samples) > 2
                
                return {
                    'ip': ip_address,
                    'vpn_detected': is_suspicious,
                    'malicious_urls': len(detected_urls),
                    'malicious_samples': len(detected_samples),
                    'source': 'virustotal.com'
                }
            except:
                pass
        return None
    except Exception:
        return None

@app.route('/shortener')
def shortener():
    """URL shortener page"""
    return render_template('shortener.html')

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)
        
        if not username or not password:
            flash('Please fill in all fields.', 'error')
            return render_template('auth/login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('index')
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(next_page)
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        confirm_email = request.form.get('confirm_email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not all([username, email, confirm_email, password, confirm_password]):
            flash('Please fill in all fields.', 'error')
            return render_template('auth/register.html')
        
        if email != confirm_email:
            flash('Emails do not match.', 'error')
            return render_template('auth/register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('auth/register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('auth/register.html')
        
        if len(username) < 3:
            flash('Username must be at least 3 characters long.', 'error')
            return render_template('auth/register.html')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('auth/register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('auth/register.html')
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        try:
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash(f'Welcome to Secora, {user.username}!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('auth/register.html')

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    recent_searches = SearchHistory.query.filter_by(user_id=current_user.id)\
                                        .order_by(SearchHistory.timestamp.desc())\
                                        .limit(10).all()
    return render_template('auth/profile.html', recent_searches=recent_searches)

@app.route('/history')
@login_required
def history():
    """User activity history page"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Get all searches for the current user with pagination
    searches = SearchHistory.query.filter_by(user_id=current_user.id)\
                                 .order_by(SearchHistory.timestamp.desc())\
                                 .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('auth/history.html', searches=searches)

@app.route('/history/delete/<int:history_id>', methods=['POST'])
@login_required
def delete_history(history_id):
    """Delete a specific history entry"""
    try:
        # Find the history entry
        history_entry = SearchHistory.query.filter_by(
            id=history_id, 
            user_id=current_user.id
        ).first()
        
        if not history_entry:
            return jsonify({'error': 'History entry not found'}), 404
        
        # Delete the entry
        db.session.delete(history_entry)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'History entry deleted'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete history entry'}), 500

@app.route('/history/load_more')
@login_required  
def load_more_history():
    """Load more history entries via AJAX"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        # Get searches for current page
        searches = SearchHistory.query.filter_by(user_id=current_user.id)\
                                     .order_by(SearchHistory.timestamp.desc())\
                                     .paginate(page=page, per_page=per_page, error_out=False)
        
        # Render just the table rows
        history_html = ""
        for search in searches.items:
            activity_type = "IP Lookup" if search.search_type == 'ip_lookup' else "URL Shortening"
            activity_data = search.ip_address if search.search_type == 'ip_lookup' else search.url_shortened
            activity_icon = "fas fa-search" if search.search_type == 'ip_lookup' else "fas fa-link"
            
            history_html += f'''
            <tr class="border-b border-gray-700 hover:bg-gray-700 transition-colors duration-200" data-history-id="{search.id}">
                <td class="px-4 py-3">
                    <div class="flex items-center space-x-2">
                        <i class="{activity_icon} text-blue-400"></i>
                        <span class="text-white font-medium">{activity_type}</span>
                    </div>
                </td>
                <td class="px-4 py-3">
                    <span class="text-gray-300 break-all">{activity_data}</span>
                </td>
                <td class="px-4 py-3">
                    <span class="text-gray-400 text-sm">{search.timestamp.strftime('%m/%d/%Y %I:%M %p')}</span>
                </td>
                <td class="px-4 py-3 text-center">
                    <button onclick="deleteHistory({search.id})" 
                            class="text-red-400 hover:text-red-300 transition-colors duration-200 p-1" 
                            title="Delete this entry">
                        <i class="fas fa-trash text-sm"></i>
                    </button>
                </td>
            </tr>
            '''
        
        return jsonify({
            'html': history_html,
            'has_next': searches.has_next,
            'next_page': searches.next_num if searches.has_next else None
        })
        
    except Exception as e:
        return jsonify({'error': 'Failed to load more history'}), 500

@app.route('/shorten', methods=['POST'])
@rate_limit(max_requests=10, window_seconds=60)  # Limit to 10 shortening requests per minute
def shorten_url():
    """Handle URL shortening requests"""
    try:
        # Validate content type
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        # Validate and sanitize input
        url = data.get('url', '')
        if not isinstance(url, str):
            return jsonify({'error': 'URL must be a string'}), 400
        
        url = sanitize_string(url.strip())
        
        if not url:
            return jsonify({'error': 'Please enter a URL'}), 400
        
        # Validate URL format
        if not is_valid_url(url):
            return jsonify({'error': 'Please enter a valid URL'}), 400
        
        # Perform the shortening
        result = shorten_with_multiple_services(url)
        
        # Log activity if user is authenticated
        if current_user.is_authenticated:
            try:
                search_record = SearchHistory(
                    user_id=current_user.id,
                    ip_address=None,  # Not applicable for URL shortening
                    search_type='url_shorten',
                    url_shortened=url
                )
                db.session.add(search_record)
                db.session.commit()
            except Exception as log_error:
                # Don't fail the request if logging fails
                app.logger.error(f"Failed to log URL shortening: {log_error}")
                db.session.rollback()
        
        return jsonify(result)
        
    except Exception as e:
        # Log the error (in production, use proper logging)
        app.logger.error(f"Shortening error: {str(e)}")
        return jsonify({'error': 'An internal error occurred'}), 500

def is_valid_url(url):
    """Validate URL format"""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and parsed.netloc
    except Exception:
        return False

def shorten_with_multiple_services(url):
    """Shorten URL using multiple services"""
    services = [
        # Direct API services (no registration needed - these work!)
        shorten_with_tinyurl,
        shorten_with_isgd,
        shorten_with_vgd,
        shorten_with_dagd,
        shorten_with_clckru,
        # Working public services
        shorten_with_cleanuri,
        # Demo only
        shorten_with_tiny_cc
    ]
    
    results = []
    
    # Run all shortening services concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as executor:
        futures = {executor.submit(service, url): service.__name__ for service in services}
        
        for future in concurrent.futures.as_completed(futures, timeout=15):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                # Add failed service result
                service_name = futures[future].replace('shorten_with_', '').replace('_', '.').title()
                results.append({
                    'service': service_name,
                    'success': False,
                    'error': str(e)
                })
    
    return {
        'original_url': url,
        'results': results,
        'success_count': len([r for r in results if r.get('success')]),
        'total_services': len(services)
    }

def shorten_with_ulvis(url):
    """Shorten URL using ulvis.net public API"""
    try:
        # ulvis.net has a simple public form
        response = requests.post('https://ulvis.net/api.php',
                               data={'url': url},
                               timeout=10)
        
        if response.status_code == 200:
            result = response.text.strip()
            if result.startswith('https://ulvis.net/') and 'error' not in result.lower():
                return {
                    'service': 'ulvis.net',
                    'success': True,
                    'short_url': result
                }
        
        return {
            'service': 'ulvis.net',
            'success': False,
            'error': 'API call failed'
        }
    except Exception as e:
        return {
            'service': 'ulvis.net',
            'success': False,
            'error': str(e)
        }

def shorten_with_cleanuri(url):
    """Shorten URL using cleanuri.com public API"""
    try:
        # cleanuri.com has a free API
        response = requests.post('https://cleanuri.com/api/v1/shorten',
                               data={'url': url},
                               timeout=10)
        
        if response.status_code == 200:
            try:
                data = response.json()
                if 'result_url' in data:
                    return {
                        'service': 'cleanuri.com',
                        'success': True,
                        'short_url': data['result_url']
                    }
            except:
                pass
        
        return {
            'service': 'cleanuri.com',
            'success': False,
            'error': 'API call failed'
        }
    except Exception as e:
        return {
            'service': 'cleanuri.com',
            'success': False,
            'error': str(e)
        }

def shorten_with_shrtfr(url):
    """Shorten URL using shrt.fr public API"""
    try:
        # shrt.fr has a simple form-based API
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'https://shrt.fr/',
            'Origin': 'https://shrt.fr'
        }
        
        response = requests.post('https://shrt.fr/',
                               data={'url': url},
                               headers=headers,
                               timeout=10)
        
        if response.status_code == 200:
            # Look for the shortened URL in the response
            content = response.text
            if 'shrt.fr/' in content:
                import re
                match = re.search(r'https://shrt\.fr/[a-zA-Z0-9]+', content)
                if match:
                    return {
                        'service': 'shrt.fr',
                        'success': True,
                        'short_url': match.group()
                    }
        
        return {
            'service': 'shrt.fr',
            'success': False,
            'error': 'Form submission failed'
        }
    except Exception as e:
        return {
            'service': 'shrt.fr',
            'success': False,
            'error': str(e)
        }

def shorten_with_tinyurl(url):
    """Shorten URL using TinyURL"""
    try:
        response = requests.get(f'https://tinyurl.com/api-create.php?url={url}', timeout=10)
        if response.status_code == 200 and response.text.startswith('https://tinyurl.com/'):
            return {
                'service': 'TinyURL',
                'success': True,
                'short_url': response.text.strip()
            }
        return {
            'service': 'TinyURL',
            'success': False,
            'error': 'Service returned invalid response'
        }
    except Exception as e:
        return {
            'service': 'TinyURL',
            'success': False,
            'error': str(e)
        }

def shorten_with_isgd(url):
    """Shorten URL using is.gd"""
    try:
        response = requests.get(f'https://is.gd/create.php?format=simple&url={url}', timeout=10)
        if response.status_code == 200 and response.text.startswith('https://is.gd/'):
            return {
                'service': 'is.gd',
                'success': True,
                'short_url': response.text.strip()
            }
        return {
            'service': 'is.gd',
            'success': False,
            'error': 'Service returned invalid response'
        }
    except Exception as e:
        return {
            'service': 'is.gd',
            'success': False,
            'error': str(e)
        }

def shorten_with_vgd(url):
    """Shorten URL using v.gd"""
    try:
        response = requests.get(f'https://v.gd/create.php?format=simple&url={url}', timeout=10)
        if response.status_code == 200 and response.text.startswith('https://v.gd/'):
            return {
                'service': 'v.gd',
                'success': True,
                'short_url': response.text.strip()
            }
        return {
            'service': 'v.gd',
            'success': False,
            'error': 'Service returned invalid response'
        }
    except Exception as e:
        return {
            'service': 'v.gd',
            'success': False,
            'error': str(e)
        }

def shorten_with_dagd(url):
    """Shorten URL using da.gd"""
    try:
        response = requests.post('https://da.gd/s', data={'url': url}, timeout=10)
        if response.status_code == 200 and 'da.gd' in response.text:
            return {
                'service': 'da.gd',
                'success': True,
                'short_url': response.text.strip()
            }
        return {
            'service': 'da.gd',
            'success': False,
            'error': 'Service returned invalid response'
        }
    except Exception as e:
        return {
            'service': 'da.gd',
            'success': False,
            'error': str(e)
        }

def shorten_with_clckru(url):
    """Shorten URL using clck.ru"""
    try:
        response = requests.get(f'https://clck.ru/--?url={url}', timeout=10)
        if response.status_code == 200 and 'clck.ru' in response.text:
            return {
                'service': 'clck.ru',
                'success': True,
                'short_url': response.text.strip()
            }
        return {
            'service': 'clck.ru',
            'success': False,
            'error': 'Service returned invalid response'
        }
    except Exception as e:
        return {
            'service': 'clck.ru',
            'success': False,
            'error': str(e)
        }

def shorten_with_cutt_ly(url):
    """Shorten URL using cutt.ly public API"""
    try:
        # cutt.ly has a free API that doesn't require registration for basic use
        response = requests.get(f'https://cutt.ly/api/api.php?key=free&short={url}', timeout=10)
        
        if response.status_code == 200:
            try:
                data = response.json()
                if 'url' in data and 'shortLink' in data['url']:
                    return {
                        'service': 'cutt.ly',
                        'success': True,
                        'short_url': data['url']['shortLink']
                    }
            except:
                pass
        
        return {
            'service': 'cutt.ly',
            'success': False,
            'error': 'Free API call failed'
        }
    except Exception as e:
        return {
            'service': 'cutt.ly',
            'success': False,
            'error': str(e)
        }

def shorten_with_tiny_cc(url):
    """Shorten URL using tiny.cc (demo)"""
    try:
        # Demo implementation - tiny.cc requires account
        import hashlib
        url_hash = hashlib.md5(url.encode()).hexdigest()[:6]
        tiny_short = f"https://tiny.cc/{url_hash}"
        
        return {
            'service': 'tiny.cc',
            'success': True,
            'short_url': tiny_short,
            'note': 'Demo URL - requires account for production'
        }
    except Exception as e:
        return {
            'service': 'tiny.cc',
            'success': False,
            'error': str(e)
        }

def shorten_with_gotiny(url):
    """Shorten URL using gotiny.cc public API"""
    try:
        # gotiny.cc has a simple public API
        response = requests.post('https://gotiny.cc/api',
                               json={'input': url},
                               headers={'Content-Type': 'application/json'},
                               timeout=10)
        
        if response.status_code == 200:
            try:
                data = response.json()
                if 'code' in data:
                    return {
                        'service': 'gotiny.cc',
                        'success': True,
                        'short_url': f"https://gotiny.cc/{data['code']}"
                    }
            except:
                pass
        
        return {
            'service': 'gotiny.cc',
            'success': False,
            'error': 'API call failed'
        }
    except Exception as e:
        return {
            'service': 'gotiny.cc',
            'success': False,
            'error': str(e)
        }

def shorten_with_gg_gg(url):
    """Shorten URL using gg.gg free service"""
    try:
        # gg.gg has a simple public form API
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'https://gg.gg/'
        }
        
        response = requests.post('https://gg.gg/create',
                               data={'custom_ending': '', 'long_url': url},
                               headers=headers,
                               timeout=10)
        
        if response.status_code == 200:
            # Look for the shortened URL in the response
            content = response.text
            if 'gg.gg/' in content:
                import re
                match = re.search(r'https://gg\.gg/[a-zA-Z0-9]+', content)
                if match:
                    return {
                        'service': 'gg.gg',
                        'success': True,
                        'short_url': match.group()
                    }
        
        return {
            'service': 'gg.gg',
            'success': False,
            'error': 'Form submission failed'
        }
    except Exception as e:
        return {
            'service': 'gg.gg',
            'success': False,
            'error': str(e)
        }

# Initialize database
def init_db():
    """Initialize the database with proper schema migration"""
    with app.app_context():
        try:
            # Check if we need to migrate from OAuth to password schema
            inspector = db.inspect(db.engine)
            if inspector.has_table('user'):
                columns = [col['name'] for col in inspector.get_columns('user')]
                
                # If old OAuth schema detected, drop all tables and recreate
                if 'oauth_provider' in columns and 'password_hash' not in columns:
                    print("🔄 Migrating from OAuth to password authentication...")
                    db.drop_all()
                    db.create_all()
                    print("✅ Database migrated successfully!")
                elif 'password_hash' not in columns:
                    # Missing password_hash column, recreate tables
                    print("🔄 Fixing database schema...")
                    db.drop_all()
                    db.create_all()
                    print("✅ Database schema fixed!")
                else:
                    # Schema looks correct, just ensure all tables exist
                    db.create_all()
                    print("✅ Database schema verified!")
            else:
                # No tables exist, create them
                db.create_all()
                print("✅ Database initialized successfully!")
                
        except Exception as e:
            print(f"❌ Database initialization error: {e}")
            # Force recreation on any error
            try:
                db.drop_all()
                db.create_all()
                print("✅ Database forcefully recreated!")
            except Exception as e2:
                print(f"❌ Failed to recreate database: {e2}")
                print("💡 Please manually delete the instance/ip_lookup.db file and restart.")

APPLE_IP_LIST_URL = "https://raw.githubusercontent.com/hroost/icloud-private-relay-iplist/refs/heads/main/ip-ranges.txt"
NORDVPN_IP_LIST_URL = "https://gist.githubusercontent.com/JamoCA/eedaf4f7cce1cb0aeb5c1039af35f0b7/raw/cb6568528820c09e94cac7ef3461bc6cbf792e7e/NordVPN-Server-IP-List.txt"

apple_ip_ranges = None
nordvpn_ips = None
ip_lists_lock = threading.Lock()

def download_and_parse_ip_lists():
    global apple_ip_ranges, nordvpn_ips
    with ip_lists_lock:
        if apple_ip_ranges is not None and nordvpn_ips is not None:
            return
        # Download Apple list
        try:
            import requests
            apple_resp = requests.get(APPLE_IP_LIST_URL, timeout=10)
            apple_ip_ranges = []
            if apple_resp.status_code == 200:
                for line in apple_resp.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        if '/' in line:
                            apple_ip_ranges.append(ipaddress.ip_network(line, strict=False))
                        else:
                            apple_ip_ranges.append(ipaddress.ip_network(line + '/32'))
                    except Exception:
                        continue
        except Exception:
            apple_ip_ranges = []
        # Download NordVPN list
        try:
            nordvpn_resp = requests.get(NORDVPN_IP_LIST_URL, timeout=10)
            nordvpn_ips = set()
            if nordvpn_resp.status_code == 200:
                for line in nordvpn_resp.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ip = ipaddress.ip_address(line)
                        nordvpn_ips.add(ip)
                    except Exception:
                        continue
        except Exception:
            nordvpn_ips = set()

def check_apple_nordvpn(ip_address):
    # Ensure lists are loaded
    download_and_parse_ip_lists()
    ip = ipaddress.ip_address(ip_address)
    # Check Apple
    for net in apple_ip_ranges:
        if ip in net:
            return 'Apple (iCloud Private Relay)'
    # Check NordVPN
    if ip in nordvpn_ips:
        return 'NordVPN'
    return None

@app.route('/lookup-count', methods=['GET'])
@login_required
def lookup_count():
    try:
        from datetime import datetime
        today = datetime.utcnow().date()
        lookups_today = SearchHistory.query.filter(
            SearchHistory.user_id == current_user.id,
            SearchHistory.search_type == 'ip_lookup',
            db.func.date(SearchHistory.timestamp) == today
        ).count()
        print(f"DEBUG: /lookup-count for user {current_user.id} on {today}: {lookups_today} lookups today")
        return jsonify({'success': True, 'lookups_today': lookups_today, 'user_id': current_user.id, 'date': str(today)})
    except Exception as e:
        print(f"DEBUG: /lookup-count error: {e}")
        return jsonify({'success': False, 'error': str(e)})

# WebSocket join handler
@socketio.on('join')
def on_join(data):
    user_id = data.get('user_id')
    if user_id:
        join_room(f'user_{user_id}')

if __name__ == '__main__':
    print("🚀 Starting Secora IP Lookup App with SocketIO...")
    socketio.run(app, debug=True) 
