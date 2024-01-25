import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

class FeatureExtraction:
    features = []
    def __init__(self,url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass


        

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())
       



     # 1.UsingIp
    # def UsingIp(self):
    #     try:
    #         ipaddress.ip_address(self.url)
    #         return -1
    #     except:
    #         return 1
    def UsingIp(self):
     try:
        parsed_url = urlparse(self.url)
        ipaddress.ip_address(parsed_url.netloc)
        return -1
     except ValueError:
        return 1

    # 2.longUrl
    def longUrl(self):
        url_length = len(self.url)
    
        if url_length < 54:
          return 1  # Short URL (potentially suspicious)
        elif 54 <= url_length <= 75:
          return 0  # Moderate length URL
        else:
         return -1  # Long URL (potentially suspicious)
 
    # 3.shortUrl
    
    def shortUrl(self):
        short_url_patterns = re.compile(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                                    r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                                    r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                                    r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                                    r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                                    r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                                    r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net')

        if short_url_patterns.search(self.url):
            return -1  # Potentially a short URL (suspicious)
        else:
           return 1   # Likely not a short URL

    # 4.Symbol@
    def symbol(self):
      if re.findall("@", self.url):
        return -1  # Symbol '@' found (potentially suspicious)
      else:
        return 1   # Symbol '@' not found
    
    # 5.Redirecting//
    def redirecting(self):
        if self.url.rfind('//')>6:
            return -1
        # phishing potential
        return 1
    
    # 6.prefixSuffix
    def prefixSuffix(self):
        try:##change
            match = re.findall('-', self.domain)
            if match:
                return -1
            # potential of phishing
            return 1
        except:
            return -1
    
    # 7.SubDomains
    def SubDomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            # moderate level of suspicious
            return 0
        return -1
           # having the phishing characteristic

    # 8.HTTPS
    def Hppts(self):
        try:
            https = self.urlparse.scheme
            # if 'https' in https:
            #     return 1
            # return -1 
            if 'https' in https:
                return -1
            return 1 
            # more suspicious
        except:
            return 1

    # 9.DomainRegLen
    def DomainRegLen(self):
     try:
        expiration_date = self.whois_response.expiration_date
        creation_date = self.whois_response.creation_date

        if expiration_date and creation_date:
            if isinstance(expiration_date, list) and len(expiration_date) > 0:
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list) and len(creation_date) > 0:
                creation_date = creation_date[0]

            age = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
            if age >= 12:
                return 1
            # legitimate website
            return -1
        else:
            # Handle the case where expiration_date or creation_date is None
            return -1
     except Exception as e:
        # Handle any exceptions that might occur during the process
       
        return -1


    # 10. Favicon
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or self.domain in head.link['href']:
                        return 1
            return -1
        except:
            return -1
            # presence of the phishing

    # 11. NonStdPort
    def NonStdPort(self):
      try:
        port = self.urlparse.port

        if port is not None:
            # Check if the port is different from the default HTTP (80) and HTTPS (443) ports
            if self.urlparse.scheme == 'http' and port != 80:
                return -1
            elif self.urlparse.scheme == 'https' and port != 443:
                return -1
            # Standard port number
            return 1
        else:
            # No port specified in the URL
            return 1
      except Exception as e:
        # Handle any exceptions that might occur during the process
        
        return -1


    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
      try:
        if self.urlparse.scheme.lower() == 'https':
            return -1
        # Presence of the secure scheme
        return 1
      except Exception as e:
        # Handle any exceptions that might occur during the process
        return -1

    
    # 13. RequestURL
    def RequestURL(self):
        try:
            for img in self.soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            try:
                percentage = success/float(i) * 100
                if percentage < 22.0:
                    return 1
                elif((percentage >= 22.0) and (percentage < 61.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1
    
    # 14. AnchorURL
    def AnchorURL(self):
       try:
        i, unsafe = 0, 0

        for a in self.soup.find_all('a', href=True):
            if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                    self.url in a['href'] or self.domain in a['href']):
                unsafe += 1
            i += 1

        try:
            percentage = (unsafe / float(i)) * 100
            if i == 0:
                return 0  # Handle the case where there are no anchor tags
            elif percentage < 31.0:
                return 1
            elif 31.0 <= percentage < 67.0:
                return 0
            else:
                return -1
        except ZeroDivisionError:
            return 0  # Handle the case where there are no anchor tags
       except Exception as e:
            return -1
      


    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
      try:
        i, success = 0, 0

        for link in self.soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
            if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                success += 1
            i += 1

        for script in self.soup.find_all('script', src=True):
            dots = [x.start(0) for x in re.finditer('\.', script['src'])]
            if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                success += 1
            i += 1

        try:
            if i == 0:
                return 0  # Handle the case where there are no link or script tags
            percentage = (success / float(i)) * 100
            if percentage < 17.0:
                return 1
            elif 17.0 <= percentage < 81.0:
                return 0
            else:
                return -1
        except ZeroDivisionError:
            return 0  # Handle the case where there are no link or script tags
      
      except Exception as e:
       
        return -1


    # 16. ServerFormHandler
    def ServerFormHandler(self):
     try:
        forms = self.soup.find_all('form', action=True)

        if len(forms) == 0:
            return 1
        else:
            for form in forms:
                if form['action'] == "" or form['action'] == "about:blank":
                    return -1
                elif self.url not in form['action'] and self.domain not in form['action']:
                    return 0

            return 1  # If no issues found in any form, return 1

     except Exception as e:
       
        return -1
 

    # 17. InfoEmail
    def InfoEmail(self):
     try:
        if re.findall(r"mailto:|@|[\(\)<>]", str(self.soup)):
            return -1
        else:
            return 1
     except Exception as e:
      
        return -1

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            if self.response.text == self.whois_response:
                return 1
            else:
                return -1
        except:
            return -1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
     try:
        if self.response is not None and len(self.response.history) <= 1:
            return 1  # No or minimal forwarding (considered safe)
        elif self.response is not None and 1 < len(self.response.history) <= 4:
            return 0  # Moderate level of forwarding (potentially suspicious)
        else:
            return -1  # High number of redirects (considered malicious)
     except Exception as e:
   
        return -1  # Handle exceptions gracefully, and consider it suspicious


    # 20. StatusBarCust
    def StatusBarCust(self):
      try:
        if self.response is not None and re.findall("<script>.+onmouseover.+</script>", self.response.text):
            return 1  # Script with onmouseover event detected (potentially suspicious)
        else:
            return -1  # No such script found (considered safe)
      except Exception as e:
    
        return -1  # Handle exceptions gracefully, and consider it suspicious


    # 21. DisableRightClick
    def DisableRightClick(self):
      try:
        if self.response is not None and re.findall(r"event\.button ?== ?2", self.response.text):
            return 1  # Script disabling right-click detected (potentially suspicious)
        else:
            return -1  # No such script found (considered safe)
      except Exception as e:
        
        return -1  # Handle exceptions gracefully, and consider it suspicious

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
     try:
        if self.response is not None and re.search(r"\balert\(", self.response.text, re.IGNORECASE):
            return 1  # Alert function detected (potentially suspicious)
        else:
            return -1  # No such function found (considered safe)
     except Exception as e:
        print(f"An error occurred: {e}")
        return -1  # Handle exceptions gracefully, and consider it suspicious

    # 23. IframeRedirection
    def IframeRedirection(self):
       
      try:
        if self.response is not None and re.search(r"<iframe|<frameBorder>", self.response.text, re.IGNORECASE):
            return 1  # Iframe or frameBorder tag detected (potentially suspicious)
        else:
            return -1  # No such tags found (considered safe)
      except Exception as e:
        
        return -1  # Handle exceptions gracefully, and consider it suspicious

    # 24. AgeofDomain


    def AgeofDomain(self):
     try:
        creation_date = self.whois_response.creation_date

        # Check if creation_date is not None and is a list
        if creation_date and isinstance(creation_date, list) and len(creation_date) > 0:
            creation_date = creation_date[0]

            # Ensure creation_date is a datetime object
            if isinstance(creation_date, datetime):
                today = date.today()
                age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)

                if age >= 6:
                    return 1  # Domain age is considered safe
                else:
                    return -1  # Domain age is considered suspicious
            else:
                return -1  # Unable to determine domain age (considered suspicious)
        else:
            return -1  # Unable to determine domain age (considered suspicious)
     except Exception as e:
        
        return -1  # Handle exceptions gracefully and consider it suspicious

    # 25. DNSRecording    
    def DNSRecording(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            today  = date.today()
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >=6:
                return 1
            return -1
        except:
            return -1

    # 26. WebsiteTraffic   
    def WebsiteTraffic(self):
      try:
        response = requests.get("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url)
        response.raise_for_status()  # Raises an HTTPError if the HTTP request returned an unsuccessful status code

        soup = BeautifulSoup(response.content, "xml")
        rank = soup.find("REACH")['RANK']

        if int(rank) < 100000:
            return 1  # High website traffic (considered safe)
        else:
            return 0  # Moderate website traffic
      except requests.exceptions.RequestException as e:
        print(f"An error occurred during the HTTP request: {e}")
        return -1  # Handle HTTP-related errors
      except Exception as e:
        return -1  # Handle other unexpected errors
 
    # 27. PageRank
    def PageRank(self):
     try:
        url = "https://www.checkpagerank.net/index.php"
        payload = {"name": self.domain}

        response = requests.post(url, data=payload)
        response.raise_for_status()  # Raises an HTTPError for bad responses

        global_rank = int(re.findall(r"Global Rank: ([0-9]+)", response.text)[0])
        if 0 < global_rank < 100000:
            return 1  # High page rank (considered safe)
        else:
            return -1  # Lower or unknown page rank
     except requests.exceptions.RequestException as e:
        print(f"An error occurred during the HTTP request: {e}")
        return -1  # Handle HTTP-related errors
     except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return -1  # Handle other unexpected errors
            

    # 28. GoogleIndex
    def GoogleIndex(self):
     try:
        results = list(search(self.url, num=5, stop=5, pause=2))
        if results:
            return 1  # URL is indexed by Google
        else:
            return -1  # URL is not indexed by Google
     except Exception as e:
        print(f"An error occurred during the Google search: {e}")
        return -1  # Handle any exceptions during the search

    # 29. LinksPointingToPage  
    def LinksPointingToPage(self):
      try:
        soup = BeautifulSoup(self.response.text, 'html.parser')
        number_of_links = len(soup.find_all('a', href=True))

        if number_of_links == 0:
            return 1  # No links pointing to the page
        elif number_of_links <= 2:
            return 0  # Moderate number of links pointing to the page
        else:
            return -1  # Many links pointing to the page (potentially suspicious)
      except Exception as e:
       
        return 0  # Return 0 for exceptions, you can customize as needed

    
    # 30. StatsReport
      
    def is_private_ip(ip_address):
     try:
        ip_obj = ipaddress.ip_address(ip_address)
        return ip_obj.is_private or ip_obj.is_reserved
     except ValueError:
        return False

    def StatsReport(self):
     try:
        url_match = re.search(
            'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', self.url)

        ip_address = socket.gethostbyname(self.domain)
        ip_match = self.is_private_ip(ip_address)

        if url_match or ip_match:
            return 1 # Suspicious URL or IP
        return -1  # Not suspicious
     except Exception as e:
        return -1
     
    
    def getFeaturesList(self):
        return self.features

