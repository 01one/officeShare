import os
import socket
import json
import logging
import time
import secrets
from datetime import datetime, timedelta
import tornado.web
from tornado.web import RequestHandler, Application, StaticFileHandler
from tornado.ioloop import IOLoop
from tornado import gen
import re
import socketio



from peewee import *

# Database setup
db = SqliteDatabase('files.db')













class BaseModel(Model):
	class Meta:
		database = db

class File(BaseModel):
	filename = CharField(unique=True)
	content = BlobField()
	upload_time = DateTimeField(default=datetime.now)

db.connect()
db.create_tables([File])

# Configuration
# change the Password ... Best practice is not to include the secret data source code directly... use envirnment variable..
PASSWORD = "12345****"

def generate_session_token():
	return secrets.token_urlsafe(16)

def check_password(user_password):
	return user_password == PASSWORD

class LoginHandler(RequestHandler):
	async def get(self):
		await self.render('login.html')

class IndexHandler(RequestHandler):
	async def get(self):
		authenticated_cookie = self.get_secure_cookie('authenticated')
		if not authenticated_cookie:
			self.redirect('/login')
			return
		
		try:
			cookie_parts = authenticated_cookie.split(b'|')
			if len(cookie_parts) == 2:
				session_token, timestamp = cookie_parts
				session_token = session_token.decode('utf-8')
				timestamp = int(timestamp)
				
				if (time.time() - timestamp) > 3600:
					self.clear_cookie('authenticated')
					self.redirect('/login')
					return
			else:
				self.clear_cookie('authenticated')
				self.redirect('/login')
				return
		except Exception as e:
			self.clear_cookie('authenticated')
			self.redirect('/login')
			return
		   
		await self.render('index.html')

class AuthenticateHandler(RequestHandler):
	async def post(self):
		user_password = self.get_body_argument('password')
		if check_password(user_password):
			session_token = generate_session_token()
			timestamp = int(time.time())
			secure_cookie_value = f"{session_token}|{timestamp}"
			self.set_secure_cookie(
				name='authenticated',
				value=secure_cookie_value,
				expires_days=None,
				secure=True,
				httponly=True,
				samesite='Strict'
			)
			self.redirect('/')
		else:
			self.set_status(401)
			self.write("Authentication failed")

# Function to sanitize and secure filenames
def secure_filename(filename):
	filename = os.path.basename(filename)
	filename = re.sub(r'[^\w\-.]', '', filename)
	return filename

# Function to check if the file extension is allowed
def allowed_file(filename):
	ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'doc', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'odg', 'apk', '7z', 'zip'}
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



class MainHandlerFileServer(RequestHandler):
	async def get(self):
		authenticated_cookie = self.get_secure_cookie('authenticated')
		if not authenticated_cookie:
			self.redirect('/login')
			return
		
		files = [file.filename for file in File.select()]
		self.set_header("Content-Type", "application/json")
		self.write(json.dumps(files))

class UploadHandler(RequestHandler):
	async def post(self):
		# Check for the authenticated cookie
		authenticated_cookie = self.get_secure_cookie('authenticated')
		if not authenticated_cookie:
			self.redirect('/login')
			self.finish()
			return

		file_info = self.request.files.get('file')[0]
		if not file_info:
			self.write('No file provided')
			return

		filename = secure_filename(file_info['filename'])

		if not allowed_file(filename):
			self.write('Invalid file format')
			return

		try:
			File.create(
				filename=filename,
				content=file_info['body']
			)
			self.write('File uploaded successfully')
		except IntegrityError:
			self.write('File already exists')

class DeleteHandler(RequestHandler):
	async def delete(self, filename):
		# Check for the authenticated cookie
		authenticated_cookie = self.get_secure_cookie('authenticated')
		if not authenticated_cookie:
			self.redirect('/login')
			self.finish()
			return

		if not filename:
			self.set_status(400)
			self.write('Filename is required')
			return


		filename = secure_filename(filename)
		try:
			file = File.get(File.filename == filename)
			file.delete_instance()
			self.write('File deleted successfully')
		except File.DoesNotExist:
			self.set_status(404)
			self.write('File not found')

	async def options(self, filename=None):
		self.set_status(204)
		self.finish()


class DownloadHandler(RequestHandler):
	async def get(self, filename):
		# Check for the authenticated cookie
		authenticated_cookie = self.get_secure_cookie('authenticated')
		if not authenticated_cookie:
			self.redirect('/login')
			self.finish()
			return
		if not filename:
			self.set_status(400)
			self.write('Filename is required')
			return


		filename = secure_filename(filename)
		try:
			file = File.get(File.filename == filename)
			self.set_header('Content-Type', 'application/octet-stream')
			self.set_header('Content-Disposition', f'attachment; filename={filename}')
			#self.write(file.content.tobytes())  # Convert memoryview to bytes
			self.write(file.content)
		except File.DoesNotExist:
			self.set_status(404)
			self.write('File not found')





class NotFoundHandler(RequestHandler):
	def prepare(self):
		self.set_status(404)
		self.render("404.html")




sio = socketio.AsyncServer(async_mode='tornado')

@sio.event
async def connect(sid, environ):
	print('Client connected:', sid)

@sio.event
async def disconnect(sid):
	print('Client disconnected:', sid)

@sio.event
async def update(sid, data):
	await sio.emit('update', {'text': 'update'}, skip_sid=sid)


# change the cookie_secrect ... Best practice is not to include the Secret data source code directly... use envirnment variable..

if __name__ == "__main__":
	settings = {
		'cookie_secret': '2938479284urkoasfdsadfsadfwe675765hdkfj',
		"max_body_size": 100 * 1024 * 1024,
		'login_url': '/login',
		'default_handler_class': NotFoundHandler
	}

	app = Application([
		(r'/login', LoginHandler),
		(r'/', IndexHandler),
		(r"/file", MainHandlerFileServer),
		(r"/delete/(.*)", DeleteHandler),
		(r"/upload", UploadHandler),
		(r"/download/(.*)", DownloadHandler),
		(r'/authenticate', AuthenticateHandler),
		(r'/static/(.*)', StaticFileHandler, {'path': os.path.join(os.getcwd(), 'static')}),
		(r"/socket.io/", socketio.get_tornado_handler(sio)),
	], debug=True, **settings)

	app.listen(9000)
	IOLoop.current().start()
