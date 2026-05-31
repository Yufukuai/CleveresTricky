import os

with open('service/src/main/java/cleveres/tricky/cleverestech/WebServer.kt', 'r') as f:
    content = f.read()

# Get Stored Keyboxes HTML
start_html = content.find('<h3>Stored Keyboxes</h3>')
if start_html != -1:
    end_html = content.find('</div>', start_html) + 6
    print("--- HTML Section ---")
    print(content[start_html-10:end_html+10])

# Get loadKeyboxes JS
start_js = content.find('async function loadKeyboxes() {')
if start_js != -1:
    end_js = content.find('async function deleteKeybox', start_js)
    print("--- JS Section ---")
    print(content[start_js:end_js])
