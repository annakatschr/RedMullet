import json
import re
from urllib import response
#import mailparser
#import requests
#from urlextract import URLExtract
import hashlib
from dotenv import load_dotenv
import os

class VirusTotalAPI():
    def __init__(self): # constructor for the VirusTotalAPI class
        load_dotenv()

        self.api  = os.getenv("API_KEY")
        self.base = os.getenv("BASE_URL")
        self.parsed_mail = ""
        self.headers = { "accept": "application/json",
                         "x-apikey": os.getenv("API_KEY")
    }
 
    def sha256_file(self,attachment):

        with open(attachment, "rb") as f:
            sha256 = hashlib.sha256()
            while True:
                data = f.read(8192)
                if not data:
                    break
                sha256.update(data)

        return sha256.hexdigest()


    def md5_file(self, attachment):
    
        with open(attachment, "rb") as f:
            md5 = hashlib.md5()
            while True:
                data = f.read(8192)
                if not data:
                    break
                md5.update(data)

        return md5.hexdigest()

    def remove_duplicates(self,seq):
        return list(dict.fromkeys(seq))
    
    def parse_email(self,mail):
        # parse stream
        with open(mail, "rb") as  f:
            mail_parsed = mailparser.parse_from_bytes(f.read())

        self.parsed_mail = mail_parsed
      #  return mail_parsed
    
    def send_request(self, url, header, payload=None):
        try:
            response = requests.get(url, headers=header, payload=payload)
            response.raise_for_status()  # Raise an exception for HTTP errors
            return response.json()  # Return the JSON response if successful
        except requests.RequestException as e:
            print(f"Error fetching data from VirusTotal API: {e}")
            return None
        
    
    def check_sender_domain(self):
        sender = self.parsed_mail.from_
        print(sender)

        url = self.base + "domains/" + sender[0][1].split("@")[1]
        print(url)

        response = self.send_request(url, self.headers)
    
        #    response = requests.get(url, headers=self.headers)
  
        print(response.text)
        print(json.dumps(response, indent=4, sort_keys=True, ensure_ascii=False))



    def check_mail_attachments(self, attachments):

    #   check if the file is already in VirusTotal's database
        for attachment in attachments:
    
            data = attachment['payload']  # raw bytes of the attachment
    
            # check md5 hash
            url = self.base + "files/" + self.md5_file(data.encode())
            # check sha256 hash
            url = self.base + "files/" + self.sha256_file(data.encode())

            response = requests.get(url, headers=self.headers)
            print(response.text)
            

    def check_header_ips(self):
        ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", str(self.parsed_mail.headers))
        ips = self.remove_duplicates(ips)
        # check that the addresses recoved are a ctualy valid ip address and not just a random string of numbers
        print(ips)

        url = self.base + "ip_addresses/" + ips[0] if ips else "invalid_ip"
        response = requests.get(url, headers=self.headers)

        print(response.text)


    def check_mail_urls(self, url):
        urls_concentrated = ''
        extractor = URLExtract()

        for url in extractor.gen_urls(self.parsed_mail.text_plain):
            urls_concentrated += url + ", "
        
        if urls_concentrated != '':
            url = self.base + "urls"
            
            payload = { "url": urls_concentrated }
            headers = {
                "accept": "application/json",
                "x-apikey": os.getenv("API_KEY"),
                "content-type": "application/x-www-form-urlencoded"
            }

           # response = requests.get(url, payload = payload, headers=headers)
            response = self.send_request(url, headers, payload)
            print(response.text)
        

if __name__ == "__main__":
    VT_mailchecker = VirusTotalAPI()
    msg = VT_mailchecker.parse_email("test_mail2.eml")
    #VT_mailchecker.check_mail_attachments(msg.attachments)
    VT_mailchecker.check_sender_domain()

        #  read from file
    #  mail_parsed = mailparser.parse_from_file(mail)
    #  print(mail_parsed.subject)
    #  print(mail_parsed.from_)
    #  print(mail_parsed.to)
    #  print(mail_parsed.text_plain)
    #  print(mail_parsed.attachments)
    #  print(mail_parsed.headers)

