from urllib.parse import urlparse

def extract_features(url):
    url = url.lower().strip()
    parsed_url = urlparse(url)

    url_length = len(url)
    dot_count = url.count('.')
    hostname = parsed_url.netloc
    subdomain_count = hostname.count('.') - 1 if hostname.count('.') > 1 else 0
    special_char_flag = 1 if any(c in url for c in ['@', '-', '//']) else 0
    https_flag = 1 if parsed_url.scheme == 'https' else 0

    brand_flag = 1 if any(b in url for b in ['google','facebook','amazon','paypal','microsoft']) else 0
    suspicious_tld_flag = 1 if any(t in url for t in ['.xyz','.top','.tk','.cf','.ml']) else 0

    return [
        url_length,
        dot_count,
        subdomain_count,
        special_char_flag,
        https_flag,
        brand_flag,
        suspicious_tld_flag
    ]
