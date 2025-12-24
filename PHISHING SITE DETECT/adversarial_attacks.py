
import random

# Simple homoglyph replacements
HOMOGLYPHS = {
    'a': 'а',   # Cyrillic a
    'e': 'е',
    'o': 'о',
    'i': 'і'
}

def dot_injection(url):
    parts = url.split("://")
    if len(parts) != 2:
        return url
    return parts[0] + "://" + parts[1].replace(".", "..", 1)

def token_insertion(url, token="secure"):
    parts = url.split("://")
    if len(parts) != 2:
        return url
    return parts[0] + "://" + token + "-" + parts[1]

def homoglyph_attack(url):
    result = ""
    for c in url:
        if c in HOMOGLYPHS and random.random() < 0.3:
            result += HOMOGLYPHS[c]
        else:
            result += c
    return result

def generate_adversarial_urls(url):
    return {
        "dot_injection": dot_injection(url),
        "token_insertion": token_insertion(url),
        "homoglyph": homoglyph_attack(url)
    }

# Test this file alone
if __name__ == "__main__":
    test_url = "http://example.com/login"
    attacks = generate_adversarial_urls(test_url)

    print("Original:", test_url)
    for name, adv in attacks.items():
        print(name, "→", adv)
