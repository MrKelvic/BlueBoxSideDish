import os
import yara
import json



class  yaraScan():

	def __init__(self,filename):
		self.filename=filename
		self.detected = False
		self.detectionTotal = 0
		self.detectionCount = 0



	def detectionPercentage(self):
		return (self.detectionCount/self.detectionTotal) * 100

	def results(self):
		results={}
		self.results = {
			'Malware':self.is_malware()+self.is_malicious_document(),
			'AntiVm' :self.is_antidb_antivm() ,
			'Crypto':self.check_crypto(),
			'File Packs':self.is_file_packed(),
		}
		return results

			
	def is_file_packed(self):
		""" These Yara YaraScan/rules aimed to detect well-known software packers, that can be used by malware to hide itself.
		"""
		#Make a list of all detected signatures
		matches = set([])
		if not os.path.exists("App/yarascripts/YaraScan/rules_compiled/packers"):
			os.mkdir("App/yarascripts/YaraScan/rules_compiled/packers")
		for n in os.listdir("App/yarascripts/YaraScan/rules/packers"):
			rule = yara.compile("App/yarascripts/YaraScan/rules/packers/" + n)
			rule.save("App/yarascripts/YaraScan/rules_compiled/packers/" + n)
			rule = yara.load("App/yarascripts/YaraScan/rules_compiled/packers/" + n)
			m = rule.match(self.filename)
			if m:
				matches.update(m)
		return list(matches)


	def is_malicious_document(self):
		matches = set([])
		if not os.path.exists("App/yarascripts/YaraScan/rules_compiled/maldocs"):
			os.mkdir("App/yarascripts/YaraScan/rules_compiled/maldocs")
		for n in os.listdir("App/yarascripts/YaraScan/rules/maldocs"):
			rule = yara.compile("App/yarascripts/YaraScan/rules/maldocs/" + n)
			rule.save("App/yarascripts/YaraScan/rules_compiled/maldocs/" + n)
			rule = yara.load("App/yarascripts/YaraScan/rules_compiled/maldocs/" + n)
			m = rule.match(self.filename)
			self.detectionTotal+=1
			if m:
				matches.update(m)
				self.detected = True
				self.detectionCount+=1
		return list(matches)


	def is_antidb_antivm(self):
		matches = set([])
		if not os.path.exists("App/yarascripts/YaraScan/rules_compiled/antidebug_antivm"):
			os.mkdir("App/yarascripts/YaraScan/rules_compiled/antidebug_antivm")
		for n in os.listdir("App/yarascripts/YaraScan/rules/antidebug_antivm"):
			rule = yara.compile("App/yarascripts/YaraScan/rules/antidebug_antivm/" + n)
			rule.save("App/yarascripts/YaraScan/rules_compiled/antidebug_antivm/" + n)
			rule = yara.load("App/yarascripts/YaraScan/rules_compiled/antidebug_antivm/" + n)
			m = rule.match(self.filename)
			if m:
				matches.update(m)
		return list(matches)
	

	def check_crypto(self):
		"""These Yara YaraScan/rules aimed to detect the existence of cryptographic algorithms.
		Detected cryptographic algorithms: 
		"""
		matches = set([])
		if not os.path.exists("App/yarascripts/YaraScan/rules_compiled/crypto"):
			os.mkdir("App/yarascripts/YaraScan/rules_compiled/crypto")
		for n in os.listdir("App/yarascripts/YaraScan/rules/crypto"):
			rule = yara.compile("App/yarascripts/YaraScan/rules/crypto/" + n)
			rule.save("App/yarascripts/YaraScan/rules_compiled/crypto/" + n)
			rule = yara.load("App/yarascripts/YaraScan/rules_compiled/crypto/" + n)
			m = rule.match(self.filename)
			if m:
				matches.update(m)
		return list(matches)


	def is_malware(self):
		""" These Yara YaraScan/rules specialised on the identification of well-known malware.
		"""
		matches = set([])
		if not os.path.exists("App/yarascripts/YaraScan/rules_compiled/malware"):
			os.mkdir("App/yarascripts/YaraScan/rules_compiled/malware")
		for n in os.listdir("App/yarascripts/YaraScan/rules/malware/"):
			if not os.path.isdir("./" + n):
				try:
					rule = yara.compile("App/yarascripts/YaraScan/rules/malware/" + n)
					rule.save("App/yarascripts/YaraScan/rules_compiled/malware/" + n)
					rule = yara.load("App/yarascripts/YaraScan/rules_compiled/malware/" + n)
					m = rule.match(self.filename)
					self.detectionTotal+=1
					if m:
						matches.update(m)
						self.detected = True
						self.detectionCount+=1
				except:
					pass  # internal fatal error or warning
			else:
				pass
		return list(matches)


	# Added by Yang
	def is_your_target(self,yara_file):
		if not os.path.exists("App/yarascripts/YaraScan/rules_compiled/your_target"):
			os.mkdir("App/yarascripts/YaraScan/rules_compiled/your_target")
		if os.path.isdir(yara_file):
			for n in os.listdir(yara_file):
				if not os.path.isdir("./" + n):
					try:
						rule = yara.compile(yara_file + "/" + n)
						rule.save("App/yarascripts/YaraScan/rules_compiled/your_target/" + n)
						rule = yara.load("App/yarascripts/YaraScan/rules_compiled/malware/" + n)
						m = rule.match(self.filename)
						if m:
							return m
					except:
						pass
				else:
					pass
		elif os.path.isfile(yara_file):
			try:
				rule = yara.compile(yara_file)
				rule.save("App/yarascripts/YaraScan/rules_compiled/your_target/" + yara_file)
				rule = yara.load("App/yarascripts/YaraScan/rules_compiled/malware/" + yara_file)
				m = rule.match(self.filename)
				if m:
					return m
			except:
				pass
		else:
			return "[x] Wrong type of input!"
