import json
from App._config import GetConfig 
from virustotal_python import Virustotal
from pprint import pprint
from base64 import urlsafe_b64encode


class VTotalAPI(): 


	def __init__(self,url):
		self.VirusTotal_API_key = "" # GetConfig().__api__("Virustotal")["KEY"]
	
		self.url  = url
		self.default = {
         "malicious":None,
         "suspicious":None,
         "undetected":None,
         "harmless":None,
         "timeout":None
      }
	 

	

	def run(self):
		try:
			vtotal = Virustotal(API_KEY=self.VirusTotal_API_key,API_VERSION=3)
			resp = vtotal.request("urls", params={"url": self.url}, method="POST")
			
			if(resp.status_code != 200):
				return self.default
			
			print(resp.data)

			scan_id = resp.data["id"]
			analysis_resp = vtotal.request("analyses/"+scan_id)
			if(analysis_resp.status_code != 200):
				return self.default
			
			print(analysis_resp.data["attributes"]["stats"])
			return analysis_resp.data["attributes"]["stats"]
		except Exception as e:
			return self.default


