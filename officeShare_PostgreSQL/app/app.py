import os
import json
import time
import secrets
import re
from datetime import datetime
from tornado.web import RequestHandler, Application, StaticFileHandler
from tornado.ioloop import IOLoop
import socketio
from sqlalchemy import Column, String, LargeBinary, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.future import select

# Configuration
DATABASE_URL = 'postgresql+asyncpg://your_user:your_password@postgres:5432/your_database'
PASSWORD = "12345****"
# Database setup with connection pooling
engine = create_async_engine(
    DATABASE_URL, 
    echo=True,
    pool_size=20,        # Maximum number of connections in the pool
    max_overflow=10,     # Extra connections to create if pool is exhausted
    pool_timeout=30,     # Time to wait for a connection before raising an error
    pool_recycle=1800    # Recycle connections every 30 minutes to avoid stale connections
)

SessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

class File(Base):
    __tablename__ = 'files'
    filename = Column(String, primary_key=True, index=True, unique=True)
    content = Column(LargeBinary)
    upload_time = Column(DateTime, default=datetime.utcnow)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

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
        except Exception:
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

        async with SessionLocal() as session:
            result = await session.execute(select(File.filename))
            files = [row[0] for row in result.fetchall()]

        self.set_header("Content-Type", "application/json")
        self.write(json.dumps(files))

class UploadHandler(RequestHandler):
    async def post(self):
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

        async with SessionLocal() as session:
            async with session.begin():
                existing_file = await session.execute(select(File).filter_by(filename=filename))
                if existing_file.scalars().first():
                    self.write('File already exists')
                    return

                new_file = File(filename=filename, content=file_info['body'])
                session.add(new_file)
                await session.commit()

        self.write('File uploaded successfully')

class DeleteHandler(RequestHandler):
    async def delete(self, filename):
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
        async with SessionLocal() as session:
            async with session.begin():
                file = await session.execute(select(File).filter_by(filename=filename))
                file_to_delete = file.scalars().first()
                if file_to_delete:
                    await session.delete(file_to_delete)
                    await session.commit()
                    self.write('File deleted successfully')
                else:
                    self.set_status(404)
                    self.write('File not found')

    async def options(self, filename=None):
        self.set_status(204)
        self.finish()

class DownloadHandler(RequestHandler):
    async def get(self, filename):
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
        async with SessionLocal() as session:
            result = await session.execute(select(File).filter_by(filename=filename))
            file = result.scalars().first()
            if file:
                self.set_header('Content-Type', 'application/octet-stream')
                self.set_header('Content-Disposition', f'attachment; filename={filename}')
                self.write(file.content)
            else:
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

async def make_app():
    await init_db()
    return Application([
        (r'/login', LoginHandler),
        (r'/', IndexHandler),
        (r"/file", MainHandlerFileServer),
        (r"/delete/(.*)", DeleteHandler),
        (r"/upload", UploadHandler),
        (r"/download/(.*)", DownloadHandler),
        (r'/authenticate', AuthenticateHandler),
        (r'/static/(.*)', StaticFileHandler, {'path': os.path.join(os.getcwd(), 'static')}),
        (r"/socket.io/", socketio.get_tornado_handler(sio)),
    ], debug=True, **{
        'cookie_secret': secrets.token_hex(16),
        "max_body_size": 100 * 1024 * 1024,
        'login_url': '/login',
        'default_handler_class': NotFoundHandler
    })

def main():
    app = IOLoop.current().run_sync(make_app)
    app.listen(9000)
    IOLoop.current().start()

if __name__ == "__main__":
    main()
