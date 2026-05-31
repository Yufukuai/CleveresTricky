import urllib.request
import urllib.parse
import json

query = "CodeQL analyses from advanced configurations cannot be processed when the default setup is enabled"
url = f"https://api.github.com/search/code?q={urllib.parse.quote(query)}"
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
try:
    response = urllib.request.urlopen(req).read().decode('utf-8')
    data = json.loads(response)
    print(data)
except Exception as e:
    print(e)
