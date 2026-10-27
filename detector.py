
from email.mime import text #helps with parsing the email body and subject
import re
import ipaddress
import joblib

Bayes = joblib.load("naive_bayes_model.pkl") #loads the saved trained bayes model 
vectorizer = joblib.load("vectorizer.pkl") # loads my saved vectorizer model


 #regex pattern to recognize urls
URL_parse_dict = {}
# URLs with a protocol
URL_pattern = r'\b(?:https?|ftp)://[^\s<>"]+'

# Domain-based URLs without a protocol
URL_pattern_without_protocol = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:[/?#][^\s<>"]*)?'

# IPv4 addresses with optional ports and paths
URL_pattern_ip = r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:[/?#][^\s<>"]*)?'


# Suggested heuristic weights (1 = weak signal, 5 = strong signal).
# These weights are not calibrated probabilities.
suspicious_keywords = {
    # Time Pressure
    "time_pressure": {
        'expires in 24 hours': 4,
        'expire in 1 day': 3,
        'within 24 hours': 4,
        'within 48 hours': 4,
        'within 1 hour': 4,
        "before it's too late": 3,
        'time is running out': 3,
        'immediate action required': 4,
        'limited time to respond': 4,
    },

    # Urgency
    "urgency": {
        'urgent': 4,
        'immediately': 1,
        'act now': 4,
        'action required': 2,
        'immediate action': 2,
        'final warning': 2,
        'final notice': 2,
        'last chance': 2,
        'within 48 hours': 4,
        'time sensitive': 2,
        'time-sensitive': 2,
        'limited time': 2,
        'expires today': 2,
        'deadline': 1,
        'respond immediately': 2,
        "don't delay": 2,
        'do not delay': 2,
        'as soon as possible': 2,
        'avoid delays': 2,
        'failure to respond': 2,
        'failure to act': 2,
        "before it's too late": 2,
        'attention required': 2,
        'important notice': 1,
        'critical alert': 2,
        'security alert': 1,
        'high priority': 1,
        'pending action': 2,
        'resolve immediately': 2,
        'take action now': 2,
    },

    # Account Threats
    "account_threats": {
        'account suspended': 4,
        'account locked': 3,
        'account blocked': 3,
        'account disabled': 3,
        'account restricted': 3,
        'account compromised': 4,
        'account terminated': 3,
        'account closure': 3,
        'permanently locked': 3,
        'permanently suspended': 3,
        'unusual activity': 3,
        'suspicious activity': 3,
        'unauthorized access': 4,
        'unauthorised access': 4,
        'login attempt': 3,
        'unrecognized login': 3,
        'unrecognised login': 3,
        'security breach': 4,
        'security issue': 3,
        'account verification': 3,
        'verify your account': 4,
        'confirm your account': 3,
        'restore access': 3,
        'restore your account': 3,
        'reactivate your account': 3,
        'recover your account': 3,
        'update your account': 3,
        'account will be closed': 5,
        'account has been flagged': 3,
        'account at risk': 3,
        'temporary suspension': 3,
        'identity verification required': 3,
    },

    # Credentials
    "credentials": {
        'password': 1,
        'passcode': 1,
        'pin number': 1,
        'security code': 2,
        'verification code': 4,
        'one-time password': 5,
        'otp': 5,
        'login credentials': 4,
        'sign in': 1,
        'log in': 1,
        'login': 1,
        'reset your password': 4,
        'confirm your password': 2,
        'update your password': 2,
        'enter your password': 5,
        'provide your password': 5,
        'verify your identity': 4,
        'confirm your identity': 2,
        'personal information': 1,
        'personal details': 2,
        'sensitive information': 2,
        'security questions': 2,
        'authentication code': 4,
        'two-factor authentication': 2,
        '2fa code': 4,
        'account details': 2,
        'date of birth': 1,
        'national insurance number': 5,
        'social security number': 5,
        'passport number': 2,
        'bank details': 2,
        'card details': 2,
        'credit card number': 5,
        'cvv': 5,
    },

    # Financial
    "financial": {
        'bank transfer': 5,
        'wire transfer': 5,
        'payment required': 4,
        'payment overdue': 4,
        'payment failed': 2,
        'payment declined': 2,
        'payment pending': 1,
        'outstanding balance': 2,
        'unpaid invoice': 2,
        'overdue invoice': 2,
        'invoice attached': 1,
        'billing issue': 2,
        'billing problem': 2,
        'update payment method': 2,
        'update billing information': 2,
        'confirm payment': 2,
        'verify payment': 2,
        'refund pending': 2,
        'refund available': 2,
        'claim your refund': 4,
        'tax refund': 2,
        'unexpected charge': 2,
        'unauthorized transaction': 2,
        'unrecognised transaction': 2,
        'suspicious transaction': 2,
        'transaction declined': 2,
        'transaction blocked': 2,
        'bank account verification': 2,
        'direct debit': 2,
        'payment confirmation': 1,
        'funds released': 2,
        'release your funds': 4,
        'processing fee': 4,
        'administration fee': 2,
        'transfer fee': 2,
        'gift card': 1,
        'bitcoin payment': 5,
        'cryptocurrency payment': 5,
    },

    # Delivery
    "delivery": {
        'delivery failed': 2,
        'failed delivery': 2,
        'delivery attempt': 2,
        'missed delivery': 2,
        'package delayed': 2,
        'parcel delayed': 2,
        'package on hold': 2,
        'parcel on hold': 2,
        'package returned': 2,
        'parcel returned': 2,
        'package may be returned': 2,
        'delivery address': 1,
        'confirm your address': 2,
        'confirm your delivery address': 2,
        'update your address': 2,
        'update your delivery details': 2,
        'reschedule delivery': 2,
        'schedule redelivery': 2,
        'redelivery fee': 2,
        'shipping fee': 2,
        'customs fee': 4,
        'customs payment': 2,
        'package awaiting confirmation': 2,
        'parcel awaiting collection': 2,
        'tracking information': 2,
        'tracking number': 1,
        'delivery confirmation required': 2,
        'incomplete address': 2,
        'incorrect address': 2,
        'unable to deliver': 2,
        'shipment suspended': 2,
        'shipment held': 2,
        'release your package': 2,
    },

    # Rewards
    "rewards": {
        'free': 1,
        'congratulations': 2,
        'you have won': 2,
        "you've won": 2,
        'winner selected': 2,
        'selected winner': 2,
        'claim your prize': 4,
        'claim your reward': 2,
        'exclusive reward': 2,
        'free gift': 2,
        'free voucher': 2,
        'gift voucher': 2,
        'gift card reward': 2,
        'cash prize': 2,
        'lottery winner': 2,
        'jackpot': 2,
        'guaranteed prize': 4,
        'special offer': 1,
        'exclusive offer': 2,
        'limited offer': 1,
        'reward waiting': 2,
        'unclaimed reward': 2,
        'free money': 4,
        'bonus payment': 2,
        'giveaway winner': 2,
        'claim now': 4,
        'redeem now': 2,
        'redeem your reward': 2,
        'you have been selected': 2,
    },

    # Impersonation
    "impersonation": {
        'security team': 1,
        'support team': 1,
        'customer support': 1,
        'account administrator': 1,
        'system administrator': 1,
        'it department': 1,
        'help desk': 1,
        'technical support': 1,
        'compliance department': 1,
        'fraud department': 1,
        'verification department': 1,
        'official notification': 1,
        'official notice': 1,
        'government notice': 1,
        'legal notice': 1,
        'court notice': 1,
        'law enforcement': 1,
        'tax authority': 1,
        'hmrc': 1,
        'microsoft support': 1,
        'google support': 1,
        'apple support': 1,
        'paypal support': 1,
        'bank security team': 1,
        'company director': 1,
        'chief executive officer': 1,
        'ceo request': 1,
        'confidential request': 1,
        'management request': 1,
    },

    # Links Attachments
    "links_attachments": {
        'click here': 1,
        'click the link': 1,
        'follow this link': 1,
        'open this link': 1,
        'visit this link': 1,
        'access the link': 1,
        'use the link below': 1,
        'download attachment': 1,
        'open attachment': 1,
        'view attachment': 1,
        'download document': 1,
        'view document': 1,
        'download invoice': 1,
        'view invoice': 1,
        'download statement': 1,
        'open the document': 1,
        'enable macros': 5,
        'enable content': 4,
        'enable editing': 4,
        'install software': 1,
        'install update': 1,
        'download update': 1,
        'secure document': 1,
        'shared document': 1,
        'document awaiting signature': 1,
        'review document': 1,
        'sign document': 1,
        'verify through this link': 1,
        'complete verification': 1,
    },

    # Threats
    "threats": {
        'legal action': 4,
        'legal consequences': 3,
        'account termination': 4,
        'permanent suspension': 3,
        'permanent closure': 3,
        'service interruption': 3,
        'service suspended': 3,
        'access revoked': 3,
        'access restricted': 3,
        'penalty fee': 4,
        'late payment penalty': 3,
        'additional charges': 3,
        'immediate termination': 3,
        'failure to comply': 3,
        'non-compliance': 3,
        'mandatory verification': 3,
        'required verification': 3,
        'avoid suspension': 3,
        'avoid termination': 3,
        'avoid account closure': 3,
        'your data will be deleted': 5,
        'files will be deleted': 3,
        'account will be disabled': 3,
        'report to authorities': 3,
        'security incident': 3,
        'compromised device': 3,
        'virus detected': 3,
        'malware detected': 3,
    },

    # Recruitment
    "recruitment": {
        'job offer': 1,
        'immediate hiring': 2,
        'work from home': 1,
        'easy income': 2,
        'guaranteed income': 2,
        'earn money fast': 2,
        'daily earnings': 2,
        'no experience required': 2,
        'registration fee': 4,
        'training fee': 4,
        'application fee': 4,
        'pay to apply': 5,
        'employment verification': 2,
        'recruitment fee': 2,
        'remote opportunity': 1,
        'limited positions': 2,
        'selected for interview': 2,
        'confirm your employment': 2,
        'submit your bank details': 5,
        'receive your salary': 2,
    },

    # Social Engineering
    "social_engineering": {
        'keep this confidential': 4,
        'do not tell anyone': 5,
        "don't tell anyone": 5,
        'keep this secret': 5,
        'strictly confidential': 4,
        'private matter': 3,
        'urgent favour': 3,
        'urgent favor': 3,
        'are you available': 1,
        'need your help urgently': 3,
        'i need a favour': 3,
        'i need a favor': 3,
        'purchase gift cards': 5,
        'buy gift cards': 5,
        'send me the codes': 5,
        'send the gift card codes': 3,
        'send money': 5,
        'transfer funds': 5,
        'change bank details': 5,
        'new bank account': 3,
        'updated bank details': 3,
        'do not call': 5,
        "don't call": 5,
        'reply only by email': 5,
        'contact me on whatsapp': 3,
        'move to whatsapp': 3,
        'avoid contacting': 3,
        'handle this discreetly': 3,
        'do not share this message': 3,
    },

    "inheritance_scams": {
            "late husband": 3,
            "widow": 2,
            "estate": 3,
            "orphanage": 2,
            "trustworthy": 2,
            "god-fearing": 2,
            "personal matter": 2,
            "bank account": 2,
            "safekeeping": 2,
            "30 days to live": 5,
            "keep 30%": 5,
            "charitable purposes": 2,
            "full name": 2,
            "country of origin": 2,
            "address": 1,
            "profession": 1,
            "beneficiary": 4,
            "inheritance": 4,
            "transfer of funds": 5
        }

}
suspicious_paths = {
    # Login and authentication
    "login": 1,
    "log-in": 1,
    "signin": 1,
    "sign-in": 1,
    "signon": 1,
    "authenticate": 1,
    "auth": 1,
    "sso": 1,
    "webmail": 1,

    # Passwords and recovery
    "password": 1,
    "passwd": 1,
    "pwd": 1,
    "renewal": 1,
    "renew": 1,
    "reset": 1,
    "recovery": 1,
    "recover": 1,
    "restore-access": 3,

    # Account verification
    "verify": 2,
    "verification": 2,
    "validate": 1,
    "validation": 1,
    "identity": 1,
    "confirm": 1,

    # Account security warnings
    "security-alert": 3,
    "security-check": 2,
    "security-update": 2,
    "security-review": 2,
    "account-alert": 3,
    "account-warning": 3,
    "suspicious-activity": 3,
    "unusual-activity": 3,
    "unauthorized-access": 4,
    "compromised": 4,
    "locked": 3,
    "unlock": 3,
    "suspended": 4,
    "disabled": 4,
    "reactivate": 3,

    # Urgency and required actions
    "urgent": 3,
    "immediate": 3,
    "action-required": 3,
    "take-action": 2,
    "act-now": 4,
    "final-notice": 4,
    "last-warning": 4,
    "important-notice": 2,
    "critical-alert": 4,
    "expiring": 4,
    "expiration": 1,
    "expiry": 1,
    "deadline": 2,
    "pending-action": 2,
    "mandatory-update": 3,

    # Banking and payments
    "banking": 1,
    "payment": 1,
    "billing": 1,
    "invoice": 1,
    "transaction": 1,
    "refund": 1,
    "credit-card": 2,
    "card-details": 3,
    "debit-card": 2,
    "bank-account": 2,
    "financial-verification": 3,

    # Delivery and shipping scams
    "delivery": 1,
    "shipping": 1,
    "shipment": 1,
    "parcel": 1,
    "package": 1,
    "tracking": 1,
    "redelivery": 2,
    "customs": 1,
    "unpaid-shipping": 4,

    # Rewards and giveaways
    "reward": 1,
    "prize": 2,
    "winner": 2,
    "winning": 2,
    "giveaway": 1,
    "gift": 1,
    "bonus": 1,
    "promotion": 1,
    "special-offer": 2,
    "exclusive-offer": 2,
    "redeem": 1,
    "redemption": 1,
    "claim": 1,
    "congratulations": 2,
    "lottery": 2,
    "sweepstakes": 2,

    # Documents and attachments
    "document": 1,
    "invoice-download": 2,
    "statement": 1,
    "secure-file": 2,
    "file-sharing": 1,
    "shared-file": 1,
    "download-file": 2,
    "attachment": 1,

    # Business and workplace impersonation
    "employee": 2,
    "staff": 2,
    "hr-portal": 1,
    "payroll": 2,
    "salary": 1,
    "benefits": 1,
    "company": 1,
    "corporate": 2,
    "admin": 2,
    "office": 2,
    "internal-portal": 2,

    # University and education phishing
    "student": 1,
    "university": 1,
    "campus": 2,
    "academic": 1,
    "school": 2,
    "education": 2,
    "tuition": 2,
    "course-registration": 1,
    "enrollment": 1,
    "enrolment": 1,

    # Cloud and email impersonation
    "mailbox": 1,
    "email": 1,
    "inbox": 1,
    "cloud": 1,
    "storage": 1,
    "sync": 2,

    # Subscription and service scams
    "subscription": 1,
    "membership": 1,
    "service": 1,
    "billing-issue": 3,
    "payment-failed": 3,
    "failed-payment": 3
}

#checks email body, subject, and sender for suspicious keywords and returns a score  and reasons for the score
def analyse_email(sender, body, subject):
    body = body.casefold()
    subject = subject.casefold()
     # suspicious keywords
    score = 0
    reasons = []
    for category, words in suspicious_keywords.items(): #go through each category
        for word, points in words.items():
                if word in body or word in subject or word in sender:
                    score += points
                    reasons.append(f"Suspicious phrase found: {word}")
    return score, reasons

def parse_url(url):
    HTTP_urls = r'^(https?)://([^/\s]+)(/[^\s]*)?$' #regex pattern to slice the url into scheme, domain, and path
    other_urls = r'^([^/\s]+)(/[^\s]*)?$' #regex pattern to slice the url into scheme, domain, and path if it does not have http or https

    match = re.search(HTTP_urls, url) #mactch is a boolean value that checks if the regex rule I applied is found in the URL
    other_match = re.search(other_urls, url)
    if match: # so if match is true, then each part of the URL is put into a variable and returned
        scheme = match.group(1)
        domain = match.group(2)
        path = match.group(3)
    elif other_match:
        scheme = "N/A"
        domain = other_match.group(1)
        path = other_match.group(2)
    else:
        scheme = "N/A"
        domain = "N/A"
        path = "N/A"

    return scheme, domain, path

#searches email in for urls in the body and parses th   em into scheme domain and paht and stores and returns them in a dictionary 
def url_finder(body):
    Parse_dic ={}
    
    urls = re.findall(URL_pattern, body) # find all is sued instead of search all because search all searches the string until the first thing is found and it stops but findall searches the whole string no matter what
    urls = urls + re.findall(URL_pattern_without_protocol, body)

    urls = remove_duplicates(urls)

    for url in urls:
        scheme, domain, path = parse_url(url)
        Parse_dic[url] = {'scheme': scheme, 'domain': domain, 'path': path} # nested dictionary is created, tkaes url as a key, holds a dictionary as a value, which holds the scheme, domain, and path of the url
    return Parse_dic

#analyzes the url and checks it for suspcious features and returns a score and reasons for the score
def analyse_url(url_info): 
    score = 0
    reasons = []
    domain = url_info['domain']
    scheme = url_info['scheme']
    path = url_info['path']

    hostname = domain.rsplit("@", 1)[-1].split(":")[0].lower()
    path = path or ""   

    if scheme == "http":
        score += 10
        reasons.append("URL uses HTTP instead of HTTPS")

    # 2. IP address instead of domain
    try:
        ipaddress.ip_address(hostname)
        score += 20
        reasons.append("URL uses an IP address")
    except ValueError:
        pass

    # 3. @ symbol in URL
    if "@" in domain or "@" in path:
        score += 25
        reasons.append("URL contains an @ symbol")

    # 4. URL shorteners
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd"]

    if hostname in shorteners:
        score += 10
        reasons.append("URL uses a shortening service")

    # 5. Suspicious keywords in path
    found_paths =[]
    for paths, points in suspicious_paths.items():
        if paths.lower() in path.lower(): #check if any suspicous path kewords is in the FULL parsed url path
            score += points
            found_paths.append(paths)
    if len(found_paths) > 0:
         reasons.append("URL contains suspicious path keywords: "+" , ".join(found_paths)) 

    # 6. Unusually long URL
    full_url = scheme + "://" + domain + path

    if len(full_url) > 100:
        score += 5
        reasons.append("URL is unusually long")

    # 7. Too many subdomains
    if hostname.count(".") >= 4:
        score += 10
        reasons.append("URL has many subdomains")

    # 8. Potentially suspicious TLD
    suspicious_tlds = [".xyz", ".top", ".click"]

    if any(hostname.endswith(tld) for tld in suspicious_tlds):
        score += 5
        reasons.append("URL uses a potentially suspicious TLD")

    # 9. Possible brand impersonation
    brands = ["paypal", "google", "amazon", "microsoft", "apple"]

    trusted_domains = {
        "paypal": ["paypal.com"],
        "google": ["google.com"],
        "amazon": ["amazon.com"],
        "microsoft": ["microsoft.com"],
        "apple": ["apple.com"]
    }

    for brand in brands:
        if brand in hostname:
            if not any(
                hostname == trusted or hostname.endswith("." + trusted)
                for trusted in trusted_domains[brand]
            ):
                score += 25
                reasons.append("Possible brand impersonation: " + brand)
                break

    # 10. Common misleading brand spellings
    fake_brands = ["paypa1", "g00gle", "arnazon", "micros0ft"]

    if any(fake in hostname for fake in fake_brands):
        score += 25
        reasons.append("Domain may contain a misleading brand spelling")

    return score, reasons
 
def remove_duplicates(urls):
    unique_urls = []
    for url in urls:
        if not any(url in existing for existing in unique_urls):
            unique_urls.append(url)

    return unique_urls

#controls the flow of program 
def pipeline(sender, body, subject, hiddenURL = ""):
    url_reasons = []
    total_url_score = 0
    email_score, email_reasons = analyse_email(sender, body, subject)

    url_dic = url_finder(body) #stores an array of all urls found in body
   
    for url in url_dic:
        url_score, url_reason = analyse_url(url_dic[url])
        total_url_score += url_score
        if len(url_reason) > 0:
            url_reasons.append({url: url_reason})
        else:
            url_reasons.append({url: ["No suspicious features found"]})


    if hiddenURL != "" and hiddenURL not in url_dic:
        scheme, domain, path = parse_url(hiddenURL) #parses hidden url in scheme domain and path
        hidden_info = {"scheme": scheme, "domain": domain, "path": path} #stores those values in a dictionary
        hidden_score, hidden_reasons = analyse_url(hidden_info) #dictionary is passed to be analysed where the reasons and scores are returned
        total_url_score += hidden_score
        url_reasons.append({hiddenURL: hidden_reasons})

   
    vectorized_text = vectorizer.transform(([subject + " " + body]))#converts the email body into speerate counted words and stores it in a vectorized_text
    probabilities = Bayes.predict_proba(vectorized_text)[0] #returns the probabilites in an array from the prediction for phsihing and normal emails
    phishing_index = list(Bayes.classes_).index("Phishing Email") #finds which index the phishing email probability is stored in 
    phishing_probability = probabilities[phishing_index] #stores that probability in the phishing probability
    bayes_points = phishing_probability * 30 #multiplies the probability by 30 to convert it into the corresponding amount of points 
    bayes_points =round(bayes_points, 0)

    risk_score = total_url_score + bayes_points + email_score 
    

    if risk_score >= 70:
        risk = "Very High Risk"
    elif risk_score >= 40:
        risk = "High Risk"
    elif risk_score >= 20:
        risk = "Moderate Risk"
    else:
        risk = "Low Risk"



    return email_reasons, url_reasons, risk, risk_score, bayes_points






#------- test below -------


