import re
from urllib.parse import urlparse

WEIGHTS = {
    'urgency': 14, 'credential_request': 18, 'financial_request': 16,
    'suspicious_url': 18, 'impersonation': 14, 'social_engineering': 10,
    'unrealistic_promise': 10, 'malware_signal': 12,
}

PATTERNS = {
    'urgency': [r'\b(immediately|urgent|right now|act now|within \d+ (minutes?|hours?)|today|last warning|account will be blocked)\b'],
    'credential_request': [r'\b(otp|one[- ]time password|password|pin|cvv|verification code|login|sign in|credentials)\b'],
    'financial_request': [r'\b(pay|payment|transfer|upi|bank|account number|card|fee|deposit|refund|loan|investment|crypto)\b'],
    'impersonation': [r'\b(bank|police|income tax|government|amazon|flipkart|microsoft|google|support|hr|recruiter|ceo|manager)\b'],
    'social_engineering': [r'\b(verify|confirm|claim|click|share|send|limited|exclusive|secret|do not tell|keep this private)\b'],
    'unrealistic_promise': [r'\b(won|winner|guaranteed|guarantee|double your money|easy money|\b\d{1,3}(?:,\d{3})+\b|free prize|reward)\b'],
    'malware_signal': [r'\b(apk|exe|zip|install this app|download and run|remote access|anydesk|teamviewer)\b'],
}

def extract_urls(text: str):
    return re.findall(r'https?://[^\s<>()\[\]"\']+', text or '', flags=re.I)

def url_indicators(url: str):
    findings=[]
    score=0
    try:
        p=urlparse(url)
        host=p.hostname or ''
        if p.scheme != 'https': findings.append(('No HTTPS', 10))
        if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', host): findings.append(('IP-address-based host', 18))
        if len(url)>120: findings.append(('Unusually long URL', 8))
        if '@' in url: findings.append(('Username-like @ character in URL', 15))
        if host.startswith('xn--') or '.xn--' in host: findings.append(('Punycode/homograph indicator', 18))
        if host.count('.') >= 4: findings.append(('Deep subdomain structure', 8))
        if re.search(r'%[0-9a-fA-F]{2}', url): findings.append(('URL encoding present', 4))
        if re.search(r'[^A-Za-z0-9./:?&=_%#-]', url): findings.append(('Unusual URL characters', 5))
        if p.path.lower().count('login') and host.split('.')[-2:] not in [['gov','in']]: findings.append(('Login path requires verification', 7))
        score=sum(v for _,v in findings)
        return min(score,60), [x for x,_ in findings]
    except Exception:
        return 35,['URL could not be parsed safely']

def classify(text: str):
    t=text or ''
    lower=t.lower()
    categories=[]
    if re.search(r'job|internship|hiring|salary|vacancy|recruit', lower): categories.append('Job / Internship Scam')
    if re.search(r'invest|returns?|profit|trading|crypto|double', lower): categories.append('Investment Scam')
    if re.search(r'otp|password|login|verify.*account|credential', lower): categories.append('Credential Theft / Phishing')
    if re.search(r'qr|upi|payment|refund|bank|card|transfer', lower): categories.append('Financial / QR Scam')
    if re.search(r'won|prize|reward|lottery|gift', lower): categories.append('Financial Scam')
    if re.search(r'account.*blocked|support|security team|police|tax', lower): categories.append('Impersonation')
    urls=extract_urls(t)
    if urls: categories.append('Suspicious URL')
    if not categories: categories=['Social Engineering / Suspicious Content']
    return list(dict.fromkeys(categories))

def analyze_message(text: str):
    score=0; indicators=[]; details=[]
    for key, pats in PATTERNS.items():
        if any(re.search(p, text or '', flags=re.I) for p in pats):
            score += WEIGHTS[key]; indicators.append(key)
    urls=extract_urls(text)
    for u in urls:
        us, ui=url_indicators(u); score += int(us*0.8); details.extend(ui)
        indicators.append('suspicious_url' if us>=12 else 'url_present')
    # avoid double counting noisy categories
    score=min(100, score)
    level='LOW' if score<25 else 'MODERATE' if score<50 else 'HIGH' if score<75 else 'CRITICAL'
    threat=classify(text)[0]
    why=[]
    mapping={
      'urgency':'Urgency or pressure to act quickly was detected.',
      'credential_request':'The content references sensitive credentials or verification codes.',
      'financial_request':'A payment, banking, transfer, loan, or investment action is requested or implied.',
      'suspicious_url':'A link is present and has characteristics that require independent verification.',
      'impersonation':'The message appears to invoke a trusted organization, role, or support identity.',
      'social_engineering':'The wording uses common social-engineering persuasion patterns.',
      'unrealistic_promise':'The message contains a prize, reward, guarantee, or unusually attractive promise.',
      'malware_signal':'The message contains indicators associated with potentially unsafe downloads or remote-access tools.'}
    for i in dict.fromkeys(indicators):
        if i in mapping: why.append(mapping[i])
    actions=['Do not click links or download files until independently verified.','Do not share OTPs, passwords, PINs, CVVs, or recovery codes.','Verify important requests through the organization’s official app/site or a known contact method.']
    if any(x in indicators for x in ['financial_request','credential_request']): actions.insert(0,'Pause the transaction and verify the request using an official channel.')
    return {'risk_score':score,'risk_level':level,'threat_type':threat,'indicators':why[:6], 'technical_indicators':list(dict.fromkeys(details))[:8], 'recommended_actions':actions[:4], 'confidence':'Moderate','urls':urls,'disclaimer':'Risk score is an automated assessment and may contain false positives or false negatives.'}

def analyze_url(url: str):
    score, inds=url_indicators(url)
    parsed=urlparse(url if '://' in url else 'https://'+url)
    host=parsed.hostname or ''
    if not parsed.scheme=='https': score=min(100,score+10)
    level='LOW' if score<25 else 'MODERATE' if score<50 else 'HIGH' if score<75 else 'CRITICAL'
    return {'risk_score':score,'risk_level':level,'threat_type':'Suspicious URL' if score>=25 else 'URL Requires Verification','indicators':inds or ['No major structural red flags detected by the local checks.'],'hostname':host,'https':parsed.scheme=='https','confidence':'Moderate','recommended_actions':['Do not enter passwords or payment information until the site is independently verified.','Open the organization’s official website/app manually instead of following an unsolicited link.'],'disclaimer':'URL structure checks do not prove that a site is malicious; reputation data is not connected in this demo unless configured.'}
