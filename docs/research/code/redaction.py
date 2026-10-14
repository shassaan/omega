import re, math
SECRET_RULES = [
 ("aws-access-key", re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b")),
 ("aws-secret-assign", re.compile(r"(?i)\baws_?secret_?(?:access_?)?key\b[\"'\s:=]{1,6}([A-Za-z0-9/+=]{40})\b")),
 ("github-token", re.compile(r"\b(gh[pousr]_[0-9A-Za-z]{36,251}|github_pat_\w{82})\b")),
 ("anthropic-key", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}")),
 ("openai-key", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}")),
 ("google-api-key", re.compile(r"\bAIza[\w\-]{35}\b")),
 ("stripe-key", re.compile(r"\b(?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,99}\b")),
 ("slack-token", re.compile(r"\bxox[abprso]-[0-9A-Za-z\-]{10,72}")),
 ("slack-webhook", re.compile(r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}")),
 ("jwt", re.compile(r"\bey[A-Za-z0-9_\-]{17,}\.ey[A-Za-z0-9_\-/\\]{17,}\.(?:[A-Za-z0-9_\-/\\]{10,}={0,2})?")),
 ("private-key", re.compile(r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]{64,}?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----|-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----")),
 ("db-url-password", re.compile(r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^\s:/@]+:)([^\s@/]{3,})(@)")),
 ("bearer", re.compile(r"(?i)\b(authorization[\"']?\s*[:=]\s*[\"']?bearer\s+)([A-Za-z0-9._~+/\-]{20,}=*)")),
 ("generic-assign", re.compile(r"(?i)\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)[A-Z0-9_]*)\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=.]{16,})[\"']?")),
]
PII_RULES = [
 ("email", re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b")),
 ("ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
 ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b")),
 ("card", re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")),
 ("phone-e164", re.compile(r"(?<![\w.])\+[1-9]\d{0,2}[ .\-]?\(?\d{1,4}\)?(?:[ .\-]?\d{2,4}){2,4}(?!\d)")),
 ("phone-us", re.compile(r"(?<![\w.\-])(?:\+?1[ .\-]?)?\(?[2-9]\d{2}\)?[ .\-]\d{3}[ .\-]\d{4}(?!\d)")),
]
def luhn(s):
    d=[int(c) for c in s if c.isdigit()]
    if not 13<=len(d)<=19: return False
    t=0
    for i,x in enumerate(reversed(d)):
        if i%2: x*=2; x-=9 if x>9 else 0
        t+=x
    return t%10==0
def iban_ok(s):
    s=s.replace(" ","").upper()
    if not 15<=len(s)<=34: return False
    n="".join(str(int(c,36)) for c in s[4:]+s[:4])
    return int(n)%97==1
def entropy(s):
    from collections import Counter
    c=Counter(s); n=len(s); return -sum(v/n*math.log2(v/n) for v in c.values())
def redact(text, pii=True):
    hits=[]
    def mk(name): 
        def f(m):
            hits.append(name); return f"[REDACTED:{name}]"
        return f
    for name,rx in SECRET_RULES:
        if name in("db-url-password",):
            text=rx.sub(lambda m:(hits.append(name),m.group(1)+"[REDACTED]"+m.group(3))[1],text)
        elif name in("bearer",):
            text=rx.sub(lambda m:(hits.append(name),m.group(1)+"[REDACTED]")[1],text)
        elif name=="generic-assign":
            def g(m):
                v=m.group(2)
                if entropy(v)<3.0 or v.lower() in("changeme","placeholder"): return m.group(0)
                hits.append(name); return m.group(0).replace(v,"[REDACTED]")
            text=rx.sub(g,text)
        else: text=rx.sub(mk(name),text)
    if pii:
        text=PII_RULES[0][1].sub(lambda m:(hits.append("email"),"[REDACTED:email]")[1],text)
        text=PII_RULES[1][1].sub(lambda m:(hits.append("ssn"),"[REDACTED:ssn]")[1],text)
        text=PII_RULES[2][1].sub(lambda m:(hits.append("iban"),"[REDACTED:iban]")[1] if iban_ok(m.group(0)) else m.group(0),text)
        text=PII_RULES[3][1].sub(lambda m:(hits.append("card"),"[REDACTED:card]")[1] if luhn(m.group(0)) else m.group(0),text)
        for n,rx in PII_RULES[4:]:
            text=rx.sub(lambda m,n=n:(hits.append(n),"[REDACTED:phone]")[1],text)
    return text,hits
