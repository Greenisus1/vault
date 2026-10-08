"""VAULT terminal interface. Secrets stay in local hidden prompts."""
from vault_core import KeyStore,AppVerifier
from terminal_ui import run

def session(ui):
 store=KeyStore()
 try:
  while True:
   locked=store.is_locked()
   index=ui.menu('Locked' if locked else 'Unlocked - idle lock 2 minutes', ['Create VAULT','Unlock','Lock now','List app keys','Create app key','Demo login','About / limits','Quit'])
   try:
    if index is None or index==7:return
    if index in (0,1):
     password=ui.prompt('Separate VAULT password, NOT device password (12+ chars for new vault)',secret=True)
     if password is None:continue
     if index==0:
      repeat=ui.prompt('Repeat VAULT password',secret=True)
      if repeat!=password:ui.message('Passwords did not match.');password=repeat=None;continue
      store.create(password);repeat=None
     else:store.unlock(password)
     password=None;ui.message('VAULT unlocked.')
    elif index==2:store.lock();ui.message('Locked.')
    elif index==3:ui.message('\n'.join(store.apps()) or 'No app keys yet.')
    elif index==4:
     app=ui.prompt('App ID (lowercase letters/digits/dot/dash/underscore)')
     if app and ui.confirm('Create key for '+app+'? App must integrate SDK. No existing login changes.'):
      public=store.register(app);ui.message('PUBLIC key for '+app+':\n'+public+'\nEnroll only through the app\'s trusted account process.')
    elif index==5:
     store.require();app='vault-demo'
     if app not in store.apps():
      if not ui.confirm('Create vault-demo key for local demo?'):continue
      store.register(app)
     verifier=AppVerifier(app);verifier.enroll(store.public_key(app));challenge=verifier.challenge()
     if ui.confirm('App: vault-demo / Action: login / Sign local one-use challenge?'):
      response=store.sign_login(challenge,app);ok=verifier.verify(response);replay=verifier.verify(response)
      ui.message(f'Local demo login accepted: {ok}\nReplay accepted: {replay}\nNo real account or website login occurred.')
    elif index==6:ui.message('Custom app-key prototype. NOT WebAuthn or device-password login.\nApps need SDK and trusted enrollment. No background broker.\nNot security audited. Cannot protect from root or same-user malware.\nLost password means lost keys. Back up encrypted vault before real use.\nLock is enforced on next operation after 2 idle minutes. No memory-zeroing guarantee.')
   except (OSError,ValueError,UnicodeError) as e:ui.message(str(e))
 finally:store.lock()
def launch():return run('VAULT 1.1.0',session)
