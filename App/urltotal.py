import json
from App._config import GetConfig 
from virustotal_python import Virustotal
from pprint import pprint
from base64 import urlsafe_b64encode


class VTotalAPI(): 


	def __init__(self,url):
		self.VirusTotal_API_key = "8265aa381c6dbe04fa0c7c7f04d9284d3bc473152f188821b83c5154e035241c" # GetConfig().__api__("Virustotal")["KEY"]
	
		self.url  = url
	 

	

	async def run(self):
		try:
			print(self.VirusTotal_API_key)
			vtotal = Virustotal(API_KEY=self.VirusTotal_API_key,API_VERSION=3)
			resp = await vtotal.request("urls", params={"url": self.url}, method="POST")
			print("Virus total:")
			print(resp)
			url_resp = resp.json()
			scan_id = url_resp["scan_id"]
			analysis_resp = vtotal.request("urls/report", params={"resource": scan_id})
			b = analysis_resp.json()
			return b["scans"]
		except Exception as e:
			print(e)
			return {"error check connection please !!"}


