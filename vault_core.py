"""VAULT encrypted custom app-key store. Not WebAuthn or OS authentication."""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
import time
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

VERSION='1.0.0'
MAX_FILE=1024*1024
KDF_N=2**15
IDLE_SECONDS=120

def b64(data):return base64.urlsafe_b64encode(data).decode('ascii')
def unb64(text):
 if not isinstance(text,str) or len(text)>16384:raise ValueError('Invalid encoded value.')
 return base64.b64decode(text.encode('ascii'),altchars=b'-_',validate=True)
def identifier(value):
 if not isinstance(value,str) or not 1<=len(value)<=100 or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789.-_' for c in value):
  raise ValueError('App IDs use 1-100 lowercase letters, digits, dot, dash or underscore.')
 return value
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode('utf-8')
def derive(password,salt):
 return b64(hashlib.scrypt(password.encode('utf-8'),salt=salt,n=KDF_N,r=8,p=1,maxmem=128*1024*1024,dklen=32)).encode('ascii')
def check_password(pw):
 if not isinstance(pw,str) or not 12<=len(pw)<=1024:raise ValueError('Use a VAULT password of 12-1024 characters. This is not your device password.')
def payload(request):
 if not isinstance(request,dict) or set(request)!={'v','app_id','action','nonce','expires'}:raise ValueError('Invalid login challenge.')
 if request['v']!=1:raise ValueError('Unsupported challenge version.')
 identifier(request['app_id'])
 if request['action']!='login':raise ValueError('Only login challenges are supported.')
 if len(unb64(request['nonce']))!=32:raise ValueError('Invalid challenge nonce.')
 if type(request['expires']) is not int:raise ValueError('Invalid challenge expiry.')
 return canonical(request)

class KeyStore:
 def __init__(self,path=None,clock=time.monotonic):
  self.path=Path(path) if path else Path.home()/'.local/share/vault/keys.json'
  self.clock=clock;self.key=None;self.data=None;self.salt=None;self.last=0;self.snapshot=None
 def lock(self):
  self.key=None;self.data=None;self.salt=None;self.snapshot=None;self.last=0
 def require(self):
  if self.key is None:raise ValueError('VAULT is locked.')
  if self.clock()-self.last>=IDLE_SECONDS:self.lock();raise ValueError('VAULT locked after inactivity.')
  self.last=self.clock()
 def is_locked(self):
  if self.key is not None and self.clock()-self.last>=IDLE_SECONDS:self.lock()
  return self.key is None
 def check_dir(self):
  parent=self.path.parent
  if any(a.is_symlink() for a in (parent,*parent.parents)):raise ValueError('VAULT folder path cannot contain symlinks.')
  parent.mkdir(parents=True,exist_ok=True,mode=0o700)
  st=parent.stat()
  if st.st_uid!=os.getuid() or st.st_mode & 0o077:raise ValueError('VAULT folder must be owned by you with mode 700.')
 def read_disk(self):
  flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|os.O_NONBLOCK
  fd=os.open(self.path,flags)
  try:
   st=os.fstat(fd)
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077:raise ValueError('VAULT file must be your regular private file (mode 600).')
   with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(MAX_FILE+1)
   if len(raw)>MAX_FILE:raise ValueError('VAULT file is too large.')
   return raw
  finally:os.close(fd)
 def create(self,password):
  check_password(password);self.check_dir()
  if self.path.exists() or self.path.is_symlink():raise ValueError('VAULT already exists. Unlock it instead.')
  self.salt=os.urandom(16);self.key=derive(password,self.salt);self.data={'apps':{}};self.last=self.clock()
  try:self.write(new=True)
  except Exception:self.lock();raise
 def unlock(self,password):
  self.lock();self.check_dir()
  if not isinstance(password,str) or len(password)>1024:raise ValueError('Invalid password length.')
  try:
   raw=self.read_disk();box=json.loads(raw)
   if set(box)!={'v','salt','ciphertext'} or box['v']!=1:raise ValueError('Unsupported VAULT format.')
   salt=unb64(box['salt'])
   if len(salt)!=16:raise ValueError('Invalid salt.')
   key=derive(password,salt);data=json.loads(Fernet(key).decrypt(box['ciphertext'].encode('ascii')))
   if not isinstance(data,dict) or set(data)!={'apps'} or not isinstance(data['apps'],dict) or len(data['apps'])>200:raise ValueError('Invalid VAULT data.')
   for app,private in data['apps'].items():
    identifier(app)
    if len(unb64(private))!=32:raise ValueError('Invalid private key.')
   self.key=key;self.salt=salt;self.data=data;self.snapshot=raw;self.last=self.clock()
  except (InvalidToken,ValueError,TypeError,KeyError,UnicodeError):raise ValueError('Wrong VAULT password or damaged file.') from None
 def write(self,new=False):
  self.require();self.check_dir()
  raw=canonical({'v':1,'salt':b64(self.salt),'ciphertext':Fernet(self.key).encrypt(canonical(self.data)).decode('ascii')})
  fd,tmp=tempfile.mkstemp(prefix='.vault-',dir=self.path.parent)
  try:
   os.fchmod(fd,0o600)
   with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
   if new:
    os.link(tmp,self.path) # exclusive creation, never overwrite an existing vault
   else:
    if self.read_disk()!=self.snapshot:raise ValueError('VAULT changed in another process. Lock and reopen.')
    os.replace(tmp,self.path)
   self.snapshot=raw
  finally:
   if os.path.exists(tmp):os.unlink(tmp)
 def apps(self):self.require();return sorted(self.data['apps'])
 def register(self,app_id):
  self.require();identifier(app_id)
  if app_id in self.data['apps']:raise ValueError('App key already exists. It will not be replaced.')
  if len(self.data['apps'])>=200:raise ValueError('Maximum 200 app keys.')
  private=Ed25519PrivateKey.generate();raw=private.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
  self.data['apps'][app_id]=b64(raw)
  try:self.write()
  except Exception:self.lock();raise
  return self.public_key(app_id)
 def public_key(self,app_id):
  self.require();identifier(app_id)
  if app_id not in self.data['apps']:raise ValueError('No key for this app. Register it first.')
  key=Ed25519PrivateKey.from_private_bytes(unb64(self.data['apps'][app_id]))
  return b64(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
 def sign_login(self,request,approved_app_id,now=None):
  """Caller must show app/action and obtain user confirmation before calling."""
  self.require();message=payload(request);identifier(approved_app_id)
  if request['app_id']!=approved_app_id:raise ValueError('Challenge is for a different app.')
  now=int(time.time()) if now is None else now
  if not now<request['expires']<=now+60:raise ValueError('Challenge expired or too far in the future.')
  self.public_key(approved_app_id)
  private=Ed25519PrivateKey.from_private_bytes(unb64(self.data['apps'][approved_app_id]))
  return {'v':1,'app_id':approved_app_id,'nonce':request['nonce'],'signature':b64(private.sign(message))}

class AppVerifier:
 """In-memory reference verifier for an app's server/login process.

 Production apps must persist user-to-public-key bindings and atomically consume
 challenges server-side. Never trust public keys supplied with a login response.
 """
 def __init__(self,app_id,clock=time.time):
  self.app_id=identifier(app_id);self.clock=clock;self.public=None;self.pending={}
 def enroll(self,public_key):
  if self.public is not None:raise ValueError('Already enrolled; explicit account recovery required to change keys.')
  raw=unb64(public_key)
  if len(raw)!=32:raise ValueError('Invalid public key.')
  self.public=Ed25519PublicKey.from_public_bytes(raw)
 def challenge(self):
  if self.public is None:raise ValueError('Enroll a public key first.')
  now=int(self.clock());self.pending={k:v for k,v in self.pending.items() if v['expires']>now}
  if len(self.pending)>=100:raise ValueError('Too many pending login challenges.')
  req={'v':1,'app_id':self.app_id,'action':'login','nonce':b64(secrets.token_bytes(32)),'expires':now+60}
  self.pending[req['nonce']]=req;return dict(req)
 def verify(self,response):
  if not isinstance(response,dict) or set(response)!={'v','app_id','nonce','signature'}:return False
  if response['v']!=1 or response['app_id']!=self.app_id:return False
  req=self.pending.pop(response['nonce'],None) if isinstance(response['nonce'],str) else None
  if req is None or int(self.clock())>=req['expires'] or self.public is None:return False
  try:self.public.verify(unb64(response['signature']),payload(req));return True
  except (InvalidSignature,ValueError,TypeError,UnicodeError):return False
