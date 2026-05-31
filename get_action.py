import urllib.request
url = "https://raw.githubusercontent.com/github/codeql-action/main/analyze/action.yml"
try:
    print(urllib.request.urlopen(url).read().decode('utf-8'))
except Exception as e:
    print(e)
