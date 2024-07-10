from subprocess import *



class signateur():
	
	
	def __init__(self,file_path):
		self.file_path = file_path
	



	def check_signateur(self):

		results = {} 

		results={
		"checksum mismatch": False,
		"no signature": False,
		"verified": False,
		"corrupted": False,
		}

		#print(results)
		command = ["osslsigncode", "verify" , self.file_path]
		p = Popen(command , stdout=PIPE, stderr=PIPE)
		(out,err) = p.communicate()
		output = out.decode()
		#print(output)
		
		if output:
			if p.returncode == 1 and "MISMATCH" in output:
				results["checksum mismatch"] = True
			if "No signature found" in output: 
				results["no signature"] = True 
			if "Signature verfification: ok" in output:
				results["verified"]= True
			if "Corrupt PE file" in output:
				results["corrupted"]= True
		return results
