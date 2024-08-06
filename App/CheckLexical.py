import re
import whois
#import urllib.request
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import pydig
import uuid
from App.WebSnapShot import WebSnapShot



class extract_data():

    def __init__(self, url):
        self.url = url
        self.urlTOhttp()
        self.response = ""
        self.GetResponse()


    async def results(self):
        results ={}
        results ={
        "Base": self.base, 
        "Domain": self.returnDomain(), 
        "Secure": self.HttpsToken(), 
        "DNS":self.DNS(),
		"UrlResponse": self.UrlRespose(), 
		"DOMRedirects": self.DOMRedirects(),
		"MetaTags": self.GetMetaTagsURL(), 
		"Links": self.GetLinksFromURL(),
		"Emails": self.Email(),
		"Forms": self.Forms(),
		"Shortners": self.ShortingSearch(), 
        "Trackers": self.Trackers(), 
        "HIDEvents":{
            "onmouseover": self.onmouseover(),
            "onmouseclick":self.onmouseclick(),
            "onkeydown":self.onkeydown()
        },
		"ScreenShot":await self.GetScreenShot(),
        "whois": self.whois(), 
        # "prefixURL": self.prefixURL(), 
        # "subdomain": self.subdomain(), 
        # "portCheck": self.portCheck(),  
        # "Iframe": self.Iframe(), 
        # "length": self.length(), 
        # "ShortingSearch": self.ShortingSearch(), 
        # "SFH": self.SFH(), 
        }
        return results
		
    def urlTOhttp(self):
        if not (re.match(r"^https?", self.url) or re.match(r"^http?", self.url)):
            self.url = "http://" + self.url
            
        parsed_url = urlparse(self.url)
        baseUrl = f"{parsed_url.scheme}://{parsed_url.hostname}"
        if parsed_url.port:
            baseUrl = f"{parsed_url.scheme}://{parsed_url.hostname}:{parsed_url.port}"
        self.base = baseUrl
        print('\n \n \n')
        print(self.url)
        print(self.base)
        print('\n \n \n')
        return self.url

    def returnDomain(self):
        parsed = urlparse(self.url)
        domain = parsed.netloc.split(".")
        return ".".join(domain)

    # check the library fo Requests all the information
    # https://pypi.org/project/whois/

    def whois(self):
        domain = self.returnDomain()
        print(domain)
        whois_response = whois.whois(domain)
        return whois_response.__dict__

    def length(self):
        if len(self.url) < 54:
            return "True"
        elif len(self.url) >= 54 and len(self.url) <= 75:
            return "False"
        else:
            return len(self.url)

    def ShortingSearch(self):
        # match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
		# 'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
		# 'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
		# 'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
		# 'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
		# 'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
		# 'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.response.text.lower())
        # result = 'False' if match else 'True'
        shortener_domains = [
            'bit\.ly', 'goo\.gl', 'shorte\.st', 'go2l\.ink', 'x\.co', 'ow\.ly', 't\.co', 'tinyurl', 'tr\.im', 'is\.gd', 'cli\.gs',
            'yfrog\.com', 'migre\.me', 'ff\.im', 'tiny\.cc', 'url4\.eu', 'twit\.ac', 'su\.pr', 'twurl\.nl', 'snipurl\.com',
            'short\.to', 'BudURL\.com', 'ping\.fm', 'post\.ly', 'Just\.as', 'bkite\.com', 'snipr\.com', 'fic\.kr', 'loopt\.us',
            'doiop\.com', 'short\.ie', 'kl\.am', 'wp\.me', 'rubyurl\.com', 'om\.ly', 'to\.ly', 'bit\.do', 't\.co', 'lnkd\.in',
            'db\.tt', 'qr\.ae', 'adf\.ly', 'goo\.gl', 'bitly\.com', 'cur\.lv', 'tinyurl\.com', 'ow\.ly', 'bit\.ly', 'ity\.im',
            'q\.gs', 'is\.gd', 'po\.st', 'bc\.vc', 'twitthis\.com', 'u\.to', 'j\.mp', 'buzurl\.com', 'cutt\.us', 'u\.bb', 'yourls\.org',
            'x\.co', 'prettylinkpro\.com', 'scrnch\.me', 'filoops\.info', 'vzturl\.com', 'qr\.net', '1url\.com', 'tweez\.me', 'v\.gd', 'tr\.im',
            'link\.zip\.net'
        ]
        pattern = r'\b(?:https?://)?(?:www\.)?(?:' + '|'.join(shortener_domains) + r')\b(?:/\S*)?'
        regex = re.compile(pattern, re.IGNORECASE)
        match = regex.findall(self.response.text.lower())
        return list(set(match))


    def prefixURL(self):
        result = "False" if re.findall(
            r'https?://[^\-]+-[^\-]+/', self.url) else "True"
        return result

    def subdomain(self):
        result = "True" if len(re.findall("\.", self.url)) == 1 else "False" if len(
            re.findall("\.", self.url)) == 2 else "False"
        return result

    def portCheck(self):
        dom = self.returnDomain()
        if ":" in dom:
            return 'False'
        else:
            return 'True'

    def HttpsToken(self):
        result = True if re.findall(r"^https://", self.url) else False
        return result

    def GetResponse(self):
        try:
            self.response = requests.get(self.url,verify=False)
            print("------------------")
            #print(self.response.content)
            #print(self.response.text)
        except:
            self.response.text = ""
        return self.response


    def GetSoup(self):
        try:
            response = requests.get(self.url,verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
        except:
            response = ""
            soup = -999
        return soup
    

    def SFH(self):
        _soup_ = self.GetSoup()
        _domain_ = self.returnDomain()

        # print(_soup_)
        for form in _soup_.find_all('form', action=True):
            if form['action'] == "" or form['action'] == "about:blank":
                return 'False'
                break
            elif self.url not in form['action'] and _domain_ not in form['action']:
                return '0'
                break
            else:
                return 'True'
                break

    def GetLinksFromURL(self):
        #get all links from the url
        _response_ = self.response.text
        # print(_response_)
        if _response_ == "":
            return []
        else:
            soup = BeautifulSoup(_response_, 'html.parser') 
            tags = soup.find_all('a')+soup.find_all('link')+soup.find_all('script')+soup.find_all('area')+soup.find_all('img')+soup.find_all('iframe')+soup.find_all('audio')+soup.find_all('video')
            links = list(set([obj.get('href') or obj.get('src') or obj.get('data-src') for obj in tags]))
            ret = [link if str(link).startswith(('http://', 'https://')) else self.base+str(link or '') for link in links]
            return ret
        
        
    def DOMRedirects(self):
        #get all meta tags from the url
        _response_ = self.response.text
        if _response_ == "":
            return {}
        else:
            soup = BeautifulSoup(_response_, 'html.parser') 
            metaTags = soup.find_all('script')
            ret = []
            patterns = {
                'location_replace': r'location\.replace\(["\']([^"\']+)["\']\)',
                'location_assign': r'location\.assign\(["\']([^"\']+)["\']\)',
                'window_location_href': r'window\.location\.href\s?=\s?["\']([^"\']+)["\']',
                'window_location_assign': r'window\.location\.assign\(["\']([^"\']+)["\']\)'
            }
            for tag in metaTags:
                for pattern in patterns.values():
                    matches = re.findall(pattern,str(tag))
                    if matches:
                        ret=ret+matches
            ret = list(set(ret))
            return ret
        
        
    def Forms(self):
        #get all meta tags from the url
        _response_ = self.response.text
        if _response_ == "":
            return {}
        else:
            soup = BeautifulSoup(_response_, 'html.parser') 
            metaTags = soup.find_all('form')
            ret = []
            for tag in metaTags:
                ret.append({
                    "content":tag,
                    "method":tag.get("method"),
                    "target":tag.get("action")
                })
            return ret


    def UrlRespose(self):
        ret = {}
        
        ret["status"] = self.response.status_code
        if self.response.history:
            ret["redirect"] = self.response.url
        return ret
    

    def onmouseover(self):
        _response_ = self.response
        if _response_ == "":
            return "False"
        else:
            if re.findall("<script>.+onmouseover.+</script>", _response_.text) or re.findall("onmouseover", _response_.text):
                return "True"
            else:
                return "False"
            
            
    def onmouseclick(self):
        _response_ = self.response
        if _response_ == "":
            return "False"
        else:
            if re.findall("<script>.+click.+</script>", _response_.text) or re.findall("click", _response_.text):
                return "True"
            else:
                return "False"
            
    def onkeydown(self):
        _response_ = self.response
        if _response_ == "": 
            return "False"
        else:
            if re.findall("<script>.+keydown.+</script>", _response_.text) or re.findall("keydown", _response_.text):
                return "True"
            else:
                return "False"
            
    def Trackers(self):
        _response_ = self.response
        if _response_ == "": 
            return []
        else:
            pattern = r'\bhttps?://\S*?(analytics|tracker)\S*\b'
            links = [link if re.findall(pattern, link) else "" for link in self.GetLinksFromURL()]
            links = [x for x in links if x != ""]
            return list(set(links))
        
    def Email(self):
        _response_ = self.response
        if _response_ == "": 
            return []
        else:
            pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            matches = re.findall(pattern, self.response.text.lower())
            return list(set(matches))
        


    def GetMetaTagsURL(self):
        #get all meta tags from the url
        _response_ = self.response.text
        if _response_ == "":
            return {}
        else:
            soup = BeautifulSoup(_response_, 'html.parser') 
            metaTags = soup.find_all('meta')
            ret = {}
            for tag in metaTags:
                ret[tag.get("id") or "tagitem"] = tag.get("content")
            return ret
        
    # def Shortners(self):
    #     _response_ = self.response
    #     if _response_ == "": 
    #         return []
    #     else:
    #         pattern = r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    #         matches = re.findall(pattern, self.response.text.lower())
    #         return list(set(matches))


    def Iframe(self):
        _response_ = self.response#self.GetResponse()
        if re.findall(r"[<iframe>|<frameBorder>]", _response_.text):
            return "True"
        else:
            return "False"
        

    def DNS(self):
        return pydig.query(self.returnDomain(), 'A')+pydig.query(self.returnDomain(), 'NS')
    

    async def GetScreenShot(self):
        path = await WebSnapShot(self.url).run()
        return path


 