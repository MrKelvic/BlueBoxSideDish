from pyppeteer import launch
import uuid

class WebSnapShot(): 


	def __init__(self, url):
		self.imgPath = "./images/webscans/"
		self.url = url


	async def run(self):
		path = self.imgPath+str(uuid.uuid4())+".png"
		print(path)
		browser = await launch(headless=True)
		page = await browser.newPage()
		await page.goto(self.url)
		await page.screenshot({'path':path})
		await browser.close()
		return path

 
