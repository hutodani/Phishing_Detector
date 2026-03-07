import tldextract
import Levenshtein as lv

legitimate_domains = ['example.com', 'google.com', 'facebook.com', 'amazon.com', 'apple.com', 'microsoft.com']

def is_misspelled_domain(user_domain, legitimate_domains):
    for legit_full in legitimate_domains:
        legit_brand = tldextract.extract(legit_full).domain
        
        # Calculate absolute edit distance (number of changes)
        distance = lv.distance(user_domain, legit_brand)
        # Calculate ratio (%)
        ratio = lv.ratio(user_domain, legit_brand)

        # Skip exact matches
        if distance == 0:
            continue

        # ADAPTIVE LOGIC
        # 1. Short names: If distance is 1 or 2, it's likely a typo
        if len(legit_brand) <= 10 and distance <= 2:
            return True
            
        # 2. Long names: Use your strict 0.9 threshold
        if len(legit_brand) > 10 and ratio >= 0.9:
            return True
            
    return False

def is_phishing_url(url, legitimate_domains):
    ext = tldextract.extract(url)
    subdomain, domain, suffix = ext.subdomain, ext.domain, ext.suffix
    
    # 1. Exact Match Check
    if f"{domain}.{suffix}" in legitimate_domains:
        print(f"Safe: {url}")
        return False

    # 2. Check for Typosquatting in the primary domain
    if is_misspelled_domain(domain, legitimate_domains):
        print(f"Potential Phishing (Typosquatting) detected: {url}")
        return True

    # 3. Check for Brand Spoofing in the subdomain
    for legit_url in legitimate_domains:
        brand = tldextract.extract(legit_url).domain
        # Check if brand is exactly in subdomain OR a typo of the brand is in subdomain
        if brand in subdomain or is_misspelled_domain(subdomain, [legit_url]):
            print(f"Potential Phishing (Subdomain Spoofing) detected: {url}")
            return True

    print(f"Unknown/Neutral: {url}")
    return False

if __name__ == "__main__":
    test_urls = [
        'http://example.co',
        'http://examp1e.com',
        'https://www.google.security-update.com',
        'http://faceb00k.com/login',
        'https://google.com',
        'https://amaz0n.pay-support.net'
    ]
    for url in test_urls:
        is_phishing_url(url, legitimate_domains)