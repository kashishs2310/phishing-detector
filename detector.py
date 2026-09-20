"""
Phishing URL Detector
Uses a trained Random Forest model to classify URLs as phishing or legitimate,
based on a subset of URL-structure features computable without external lookups.
"""

import re
from urllib.parse import urlparse
import joblib
import pandas as pd


def extract_features(url):
    features = {}

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    domain = parsed.netloc

    # having_IPhaving_IP_Address
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    features['having_IPhaving_IP_Address'] = -1 if ip_pattern.match(domain) else 1

    # URLURL_Length
    length = len(url)
    features['URLURL_Length'] = 1 if length < 54 else (0 if length <= 75 else -1)

    # Shortining_Service
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']
    features['Shortining_Service'] = -1 if any(s in url for s in shorteners) else 1

    # having_At_Symbol
    features['having_At_Symbol'] = -1 if '@' in url else 1

    # double_slash_redirecting
    features['double_slash_redirecting'] = -1 if url.rfind('//') > 7 else 1

    # Prefix_Suffix
    features['Prefix_Suffix'] = -1 if '-' in domain else 1

    # having_Sub_Domain
    dot_count = domain.count('.')
    features['having_Sub_Domain'] = 1 if dot_count <= 1 else (0 if dot_count == 2 else -1)

    return features


model = joblib.load('phishing_model.pkl')

# Paste your real column list here (from running list(X.columns) in your notebook)
all_columns = ['having_IPhaving_IP_Address',
 'URLURL_Length',
 'Shortining_Service',
 'having_At_Symbol',
 'double_slash_redirecting',
 'Prefix_Suffix',
 'having_Sub_Domain',
 'SSLfinal_State',
 'Domain_registeration_length',
 'Favicon',
 'port',
 'HTTPS_token',
 'Request_URL',
 'URL_of_Anchor',
 'Links_in_tags',
 'SFH',
 'Submitting_to_email',
 'Abnormal_URL',
 'Redirect',
 'on_mouseover',
 'RightClick',
 'popUpWidnow',
 'Iframe',
 'age_of_domain',
 'DNSRecord',
 'web_traffic',
 'Page_Rank',
 'Google_Index',
 'Links_pointing_to_page',
 'Statistical_report']


def predict_url(url):
    try:
        extracted = extract_features(url)
        row = {col: extracted.get(col, 0) for col in all_columns}
        df_input = pd.DataFrame([row])
        prediction = model.predict(df_input)[0]
        confidence = model.predict_proba(df_input)[0]

        verdict = "LEGITIMATE" if prediction == 1 else "PHISHING"
        print(f"URL: {url}")
        print(f"Verdict: {verdict}")
        print(f"Confidence: {max(confidence):.2%}")
    except Exception as e:
        print(f"Error processing URL: {e}")
        print("Please check the URL format and try again.")
    print("-" * 40)


if __name__ == "__main__":
    test_urls = [
        "https://www.wikipedia.org",
        "https://www.github.com",
        "http://bit.ly/random123",
        "http://192.168.1.1/login",
        "http://secure-paypal-verify.account-update.tk",
        "http://amaz0n-security-check.com",
        "google.com",  # no protocol, tests the auto-fix
    ]
    for url in test_urls:
        predict_url(url)