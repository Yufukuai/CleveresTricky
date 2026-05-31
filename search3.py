import urllib.request
import urllib.parse
import json

query = 'site:github.com "CodeQL analyses from advanced configurations cannot be processed when the default setup is enabled"'
url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
try:
    html = urllib.request.urlopen(req).read().decode('utf-8')
    import re
    from html.parser import HTMLParser

    class MyHTMLParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.text = []
            self.capture = False
        def handle_starttag(self, tag, attrs):
            if tag == 'a':
                for attr in attrs:
                    if attr[0] == 'class' and 'result__snippet' in attr[1]:
                        self.capture = True
        def handle_data(self, data):
            if self.capture:
                self.text.append(data)
        def handle_endtag(self, tag):
            if tag == 'a':
                self.capture = False

    parser = MyHTMLParser()
    parser.feed(html)
    print(" ".join(parser.text))
except Exception as e:
    print(e)
