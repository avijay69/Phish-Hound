import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import ipaddress, re
from urllib.parse import urlparse, urlencode 
import requests
from pysafebrowsing import SafeBrowsing
import whois

def safebrowsing(url):
    s = SafeBrowsing('AIzaSyB0bGAKDz5WU0-osDQWKc7H6CPaDsUqT-E')
    r = s.lookup_urls([url])
    malicious_status = r[url]['malicious']
    return malicious_status

def checkforip(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip = 0
    return ip

def checkat(url):
    if "@" in url:
        at = 1   
    else:
        at = 0   
    return at

def urllength(url):
    if len(url) < 60:
        l = 0       
    else:
        l = 1       
    return l

def depthchk(url):
    x = urlparse(url).path.split('/')
    d = 0
    for i in range(len(x)):
        if len(x[i]) != 0:
            d = d + 1
    return d

def rdrchk(url):
    p = url.rfind('//')
    if p > 6:
        if p > 7:
            return 1
        else:
            return 0
    else:
        return 0
    
def httpschk(url):
    d = urlparse(url).netloc
    if 'https' in url:
        return 0
    else:
        return 1

ss = r"\.bit\.ly|\.goo\.gl|\.shorte\.st|\.go2l\.ink|\.x\.co|\.ow\.ly|\.tinyurl|\.tr\.im|\.is\.gd|\.cli\.gs|\." \
           r"yfrog\.com|\.migre\.me|\.ff\.im|\.tiny\.cc|\.url4\.eu|\.twit\.ac|\.su\.pr|\.twurl\.nl|\.snipurl\.com|\." \
           r"short\.to|\.BudURL\.com|\.ping\.fm|\.post\.ly|\.Just\.as|\.bkite\.com|\.snipr\.com|\.fic\.kr|\.loopt\.us|\." \
           r"doiop\.com|\.short\.ie|\.kl\.am|\.wp\.me|\.rubyurl\.com|\.om\.ly|\.to\.ly|\.bit\.do|\.t\.co|\.lnkd\.in|\.db\.tt|\." \
           r"qr\.ae|\.adf\.ly|\.goo\.gl|\.bitly\.com|\.cur\.lv|\.tinyurl\.com|\.ow\.ly|\.bit\.ly|\.ity\.im|\.q\.gs|\.is\.gd|\." \
           r"po\.st|\.bc\.vc|\.twitthis\.com|\.u\.to|\.j\.mp|\.buzurl\.com|\.cutt\.us|\.u\.bb|\.yourls\.org|\.x\.co|\." \
           r"prettylinkpro\.com|\.scrnch\.me|\.filoops\.info|\.vzturl\.com|\.qr\.net|\.1url\.com|\.tweez\.me|\.v\.gd|\." \
           r"tr\.im|\.link\.zip\.net"

def shortcheck(url):
    m = re.search(ss, url)
    if m:
        return 1
    else:
        return 0

def dashchk(url):
    if '-' in urlparse(url).netloc:
        return 1
    else:
        return 0

def iframerdrchk(r):
    if r == "":
        return 0
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", r.text):
            return 0
        else:
            return 1

def mouseoverchk(r): 
    if r == "" :
        return 0
    else:
        if re.findall("<script>.+onmouseover.+</script>", r.text):
            return 1
        else:
            return 0

def disablerclickchk(r):
    if r == "":
        return 0
    else:
        if re.findall(r"event.button ?== ?2", r.text):
            return 1
        else:
            return 0

def webforwardchk(r):
    if r == "":
        return 0
    else:
        if len(r.history) <= 2:
            return 0
        else:
            return 1
           
def check_whois_info(url):
    try:
        # Fetch WHOIS information
        w = whois.whois(domain)
         
        # Check if domain is registered by looking at the 'domain_name' attribute
        if w.domain_name:
            print("URL has DNS record")
            return 0
        else:
            print("URL has no DNS record")
            return 1 # Domain is not registered
    except:
        return 0 # Domain is not registered or an error occurred

def check(url):
    reasons = []
       
    ats = checkat(url)
    if ats == 1:
        reasons.append("URL contains '@' symbol")
       
    urllen = urllength(url)
    if urllen == 1:
        reasons.append("URL is too long")
       
    urldepth = depthchk(url)
    if urldepth > 5:
        reasons.append("URL has too many subdirectories")
       
    rdr = rdrchk(url)
    if rdr == 1:
        reasons.append("URL contains redirection ('//')")
       
    https = httpschk(url)
    if https == 1:
        reasons.append("URL is not using secured protocol (HTTPS)")
       
    shorturl = shortcheck(url)
    if shorturl == 1:
        reasons.append("URL uses a shortening service")
       
    dash = dashchk(url)
    if dash == 1:
        reasons.append("URL contains '-' symbol in the domain")
       
    ip = checkforip(url)
    if ip == 1:
        reasons.append("URL contains an IP address")
       
    sb = safebrowsing(url)
    if sb == 1:
        reasons.append("URL is flagged by Google Safe Browsing")
       
    dns = 0
     
    dns = check_whois_info(url)
    if dns == 1:
        reasons.append("URL has no DNS records")
         
    try:
        res = requests.get(url)
    except:
        res = ""
       
    iframe = iframerdrchk(res)
    if iframe == 1:
        reasons.append("URL contains iframe redirection")
       
    mouseover = mouseoverchk(res)
    if mouseover == 1:
        reasons.append("URL contains 'onmouseover' event in script")
       
    rightclick = disablerclickchk(res)
    if rightclick == 1:
        reasons.append("URL disables right-click")
       
    webforward = webforwardchk(res)
    if webforward == 1:
        reasons.append("URL has multiple web forwardings")
       
    if reasons:
        return "Phishing URL detected: " + ", ".join(reasons), "red"
    else:
        return "Safe URL detected", "green"

def on_button_click():
    url = url_entry.get()
     
    result_label.config(text="                                                  Checking URL..                                                  ", fg="blue")
    root.update_idletasks()
    result, color = check(url)
    result_label.config(text=result, fg=color)

# Create the main application window
root = tk.Tk()
root.title("PHISH HOUND v 1.0")
root.geometry("1280x720")

# Load and display the background image
bg_image = Image.open("bg.jpeg")
bg_photo = ImageTk.PhotoImage(bg_image)
bg_label = tk.Label(root, image=bg_photo)
bg_label.place(relwidth=1, relheight=1)

url_entry = tk.Entry(root, width=50, font=("Arial", 18))
url_entry.place(relx=0.5, rely=0.4, anchor="center")

process_button = tk.Button(root, text="CHECK URL", command=on_button_click, font=("Arial", 18), bg="light blue")
process_button.place(relx=0.5, rely=0.5, anchor="center")

result_label = tk.Label(root, text="Enter URL to check", font=("Arial", 18))
result_label.place(relx=0.5, rely=0.6, anchor="center")

root.mainloop()
