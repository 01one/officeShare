import os
import json
import time
import secrets
import re
from io import BytesIO
import tornado.web
from tornado.web import RequestHandler, Application, StaticFileHandler
from tornado.ioloop import IOLoop
import motor.motor_tornado
from motor.motor_tornado import MotorGridFSBucket
import socketio


mongo_url= "mongodb://localhost:27017/"

client = motor.motor_tornado.MotorClient(mongo_url)
db = client["file_server_db"]
fs = MotorGridFSBucket(db)

# Configuration
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

def secure_filename(filename):
    filename = os.path.basename(filename)
    filename = re.sub(r'[^\w\-.]', '', filename)
    return filename

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'doc', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'odg', 'apk', '7z', 'zip'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class MainHandlerFileServer(RequestHandler):
    async def get(self):
        authenticated_cookie = self.get_secure_cookie('authenticated')
        if not authenticated_cookie:
            self.redirect('/login')
            return

        files = await db.fs.files.find().to_list(None)
        file_names = [file['filename'] for file in files]
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps(file_names))

class UploadHandler(RequestHandler):
    async def post(self):
        authenticated_cookie = self.get_secure_cookie('authenticated')
        if not authenticated_cookie:
            self.redirect('/login')
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
            file_body = file_info['body']
            file_stream = BytesIO(file_body)
            file_id = await fs.upload_from_stream(filename, file_stream)
            self.write(f'File uploaded successfully with ID: {str(file_id)}')
        except Exception as e:
            self.write('Error during file upload')

class DeleteHandler(RequestHandler):
    async def delete(self, filename):
        authenticated_cookie = self.get_secure_cookie('authenticated')
        if not authenticated_cookie:
            self.redirect('/login')
            return

        if not filename:
            self.set_status(400)
            self.write('Filename is required')
            return

        filename = secure_filename(filename)
        try:
            file = await db.fs.files.find_one({'filename': filename})
            if file:
                await fs.delete(file['_id'])
                self.write('File deleted successfully')
            else:
                self.set_status(404)
                self.write('File not found')
        except Exception as e:
            self.set_status(500)
            self.write('Error during file deletion')

    async def options(self, filename=None):
        self.set_status(204)
        self.finish()

class DownloadHandler(RequestHandler):
    async def get(self, filename):
        authenticated_cookie = self.get_secure_cookie('authenticated')
        if not authenticated_cookie:
            self.redirect('/login')
            return

        if not filename:
            self.set_status(400)
            self.write('Filename is required')
            return

        filename = secure_filename(filename)
        try:
            file = await db.fs.files.find_one({'filename': filename})
            if file:
                file_stream = await fs.open_download_stream(file['_id'])
                self.set_header('Content-Type', 'application/octet-stream')
                self.set_header('Content-Disposition', f'attachment; filename={filename}')
                
                while True:
                    chunk = await file_stream.read(4096)
                    if not chunk:
                        break
                    self.write(chunk)
                    await self.flush()

                self.finish()
            else:
                self.set_status(404)
                self.write('File not found')
        except Exception as e:
            self.set_status(500)
            self.write('Error during file download')

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

if __name__ == "__main__":
    cookie_secret = secrets.token_hex(16)
    settings = {
        'cookie_secret': cookie_secret,
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
