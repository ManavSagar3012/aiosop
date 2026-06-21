import hashlib
content = b'[{"type": "js_match", "file": "https://uat-bugbounty.nonprod.syfe.com/", "match": "AKIA4S7V6B3X2P9Q1L5M"}]'
print(hashlib.sha256(content).hexdigest())
