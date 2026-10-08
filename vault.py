#!/usr/bin/env python3
"""VAULT: encrypted keys for custom app login, not WebAuthn or device login."""
from vault_core import KeyStore, AppVerifier, VERSION

def launch(test_hook=None):
 import tkinter as tk
 from tkinter import ttk,messagebox,simpledialog
 root=tk.Tk();root.title('VAULT '+VERSION);root.geometry('850x590');root.minsize(760,540)
 store=KeyStore();timer=None
 root.configure(bg='#15242d')
 tk.Label(root,text='VAULT',font=('DejaVu Sans',24,'bold'),bg='#15242d',fg='#c4eddb').pack(anchor='w',padx=24,pady=(18,4))
 tk.Label(root,text='Custom app keys. Not website passkeys or your device password.',font=('DejaVu Sans',11),bg='#15242d',fg='#dde9ee').pack(anchor='w',padx=24,pady=(0,14))
 panel=ttk.Frame(root,padding=20);panel.pack(fill='both',expand=True,padx=20,pady=(0,20));panel.columnconfigure(0,weight=1);panel.rowconfigure(3,weight=1)
 status=tk.StringVar(value='Locked. Create or unlock your local VAULT.');ttk.Label(panel,textvariable=status).grid(row=0,column=0,sticky='w',pady=(0,12))
 bar=ttk.Frame(panel);bar.grid(row=1,column=0,sticky='ew',pady=(0,14))
 tree=ttk.Treeview(panel,columns=('app',),show='headings',selectmode='browse');tree.heading('app',text='Registered app IDs (private keys stay encrypted on disk)');tree.grid(row=3,column=0,sticky='nsew')
 output=tk.Text(panel,height=5,wrap='word',font=('DejaVu Sans Mono',10),state='disabled');output.grid(row=4,column=0,sticky='ew',pady=(12,0))
 def log(text):
  output.config(state='normal');output.delete('1.0','end');output.insert('end',text);output.config(state='disabled')
 def refresh():
  tree.delete(*tree.get_children())
  if store.is_locked():status.set('Locked. Private keys are not available.');return
  for a in store.apps():tree.insert('', 'end',iid=a,values=(a,))
  status.set('Unlocked. Idle lock after 2 minutes. Lock when finished.')
 def guarded(fn):
  try:fn();refresh()
  except Exception as e:messagebox.showerror('VAULT',str(e),parent=root);refresh()
 def create():
  pw=simpledialog.askstring('Create VAULT','Choose a separate VAULT password (12+ characters).\nDo not enter your device login password.',show='*',parent=root)
  if pw is None:return
  repeat=simpledialog.askstring('Repeat','Repeat your VAULT password.',show='*',parent=root)
  if repeat!=pw:messagebox.showerror('VAULT','Passwords did not match.',parent=root);return
  guarded(lambda:store.create(pw));pw=repeat=None
 def unlock():
  pw=simpledialog.askstring('Unlock VAULT','VAULT password (not your device password):',show='*',parent=root)
  if pw is not None:guarded(lambda:store.unlock(pw))
  pw=None
 def lock():store.lock();log('Locked.');refresh()
 def register():
  app=simpledialog.askstring('Register app key','App ID (lowercase letters, digits, dot, dash, underscore):',parent=root)
  if app is None:return
  if not messagebox.askyesno('Create app key',f'Create a key for {app}?\nAn app must integrate the VAULT SDK to use it. No existing app is changed.',parent=root):return
  def action():
   public=store.register(app);log('PUBLIC key for '+app+' (safe to enroll in its trusted login process):\n'+public+'\nNever replace an account key without its recovery checks.')
  guarded(action)
 def demo():
  # An isolated reference app, not a remote account login or automatic enrollment.
  def action():
   store.require();app='vault-demo'
   if app not in store.apps():
    if not messagebox.askyesno('Demo app key','Create a local vault-demo key for the included demo?',parent=root):return
    store.register(app)
   verifier=AppVerifier(app);verifier.enroll(store.public_key(app));request=verifier.challenge()
   if not messagebox.askyesno('Approve login','App: vault-demo\nAction: login\nLocal demo only. Sign this one-use challenge?',parent=root):return
   response=store.sign_login(request,app);accepted=verifier.verify(response);replay=verifier.verify(response)
   log(f'Local demo login accepted: {accepted}\nReusing the same signed response accepted: {replay}\nNo website, real account, or other app was logged in.')
  guarded(action)
 for title,cmd in [('Create',create),('Unlock',unlock),('Lock now',lock),('Create app key',register),('Test demo login',demo)]:ttk.Button(bar,text=title,command=cmd).pack(side='left',padx=(0,8))
 ttk.Label(panel,text='Apps need SDK integration. This does not modify app logins automatically.\nLost VAULT password means lost keys. Back up the encrypted file before enrolling real accounts.',wraplength=720).grid(row=2,column=0,sticky='w',pady=(0,14))
 def tick():
  nonlocal timer
  if store.is_locked() and 'Unlocked' in status.get():refresh();log('Locked after inactivity.')
  timer=root.after(1000,tick)
 def close():
  if timer:root.after_cancel(timer)
  store.lock();root.destroy()
 root.protocol('WM_DELETE_WINDOW',close);tick()
 if test_hook:test_hook(root,store,refresh,log,close)
 root.mainloop()

def main():
 import argparse
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--version',action='version',version=VERSION);p.add_argument('--gui',action='store_true');args=p.parse_args()
 if args.gui:launch();return 0
 from vault_terminal import launch as terminal_launch
 return terminal_launch()
if __name__=='__main__':raise SystemExit(main())
