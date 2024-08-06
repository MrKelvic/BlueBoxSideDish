import uuid
import asyncio
from pyppeteer import launch

class WebSnapShot(): 


	def __init__(self, url):
		self.url = url


	async def screenshot(self):
		uid = str(uuid.uuid4())
		path = "static/webscans/" + uid + ".png"
		# print(path)
		print("WbeSnapShot.py **8")
		print(self.url)
		
		try:
			browser = await launch( handleSIGINT=False,handleSIGTERM=False,handleSIGHUP=False,options={'args': ['--no-sandbox']})
			page = await browser.newPage()
			print(page)
			await page.goto(self.url)
			body_height = await page.evaluate('document.body.scrollHeight')
			await page.setViewport({'width': 1920, 'height': body_height})
			await page.screenshot({'path': path,'fullPage': True})
			await browser.close()
		except KeyboardInterrupt:
			print("KeyboardInterrupt: Stopping the screenshot process.")
			await browser.close()  
			return None
		
		return path
		 

	async def run(self):
		return await self.screenshot()
 
