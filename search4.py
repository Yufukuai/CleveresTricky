import urllib.request
import urllib.parse
import json

url = "https://api.github.com/repos/github/codeql-action/issues?state=all&q=" + urllib.parse.quote("CodeQL analyses from advanced configurations cannot be processed when the default setup is enabled")
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/vnd.github.v3+json'})
try:
    response = urllib.request.urlopen(req).read().decode('utf-8')
    data = json.loads(response)
    for issue in data[:5]:
        print(f"Title: {issue['title']}")
        print(f"URL: {issue['html_url']}")
        print(f"Body snippet: {issue['body'][:200]}...")
        print("---")
except Exception as e:
    print(e)
