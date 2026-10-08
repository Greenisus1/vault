#!/usr/bin/env python3
"""Isolated demo: never enrolls or logs into a real account."""
import getpass,tempfile
from pathlib import Path
from vault_core import KeyStore,AppVerifier

def main():
 with tempfile.TemporaryDirectory(prefix='vault-demo-') as folder:
  store=KeyStore(Path(folder)/'private/keys.json')
  password=getpass.getpass('Choose a temporary DEMO password (12+ characters, not your device password): ')
  store.create(password);public=store.register('demo-app');store.lock();store.unlock(password);password=None
  verifier=AppVerifier('demo-app');verifier.enroll(public);challenge=verifier.challenge()
  if input('App: demo-app. Action: login. Sign this local demo challenge? [y/N] ').lower()!='y':store.lock();return
  response=store.sign_login(challenge,'demo-app')
  print('Login accepted:',verifier.verify(response));print('Replay accepted:',verifier.verify(response));store.lock()
if __name__=='__main__':main()
