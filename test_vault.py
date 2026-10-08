import unittest,tempfile,json,os
from pathlib import Path
from vault_core import *
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'private/keys.json';self.clock=[100.0];self.s=KeyStore(self.path,lambda:self.clock[0]);self.s.create('test-only-password')
 def tearDown(self):self.s.lock();self.tmp.cleanup()
 def test_roundtrip(self):
  p=self.s.register('myapp');self.s.lock();self.s.unlock('test-only-password');self.assertEqual(self.s.public_key('myapp'),p)
 def test_wrong_password(self):
  self.s.lock();self.assertRaises(ValueError,self.s.unlock,'wrong');self.assertTrue(self.s.is_locked())
 def test_encrypted(self):
  self.s.register('myapp');raw=self.path.read_bytes();self.assertNotIn(b'myapp',raw);self.assertNotIn(b'test-only-password',raw);self.assertNotIn(self.s.data['apps']['myapp'].encode(),raw)
 def test_permissions(self):
  self.assertEqual(self.path.stat().st_mode&0o777,0o600);self.assertEqual(self.path.parent.stat().st_mode&0o777,0o700)
 def test_no_overwrite(self):self.assertRaises(ValueError,KeyStore(self.path).create,'another-password')
 def test_duplicate(self):
  p=self.s.register('myapp');self.assertRaises(ValueError,self.s.register,'myapp');self.assertEqual(p,self.s.public_key('myapp'))
 def test_id(self):
  for a in ('','Bad','../a','a b','x'*101):self.assertRaises(ValueError,self.s.register,a)
 def verifier(self):
  self.s.register('myapp');v=AppVerifier('myapp',lambda:1000);v.enroll(self.s.public_key('myapp'));return v
 def test_login_replay(self):
  v=self.verifier();r=v.challenge();response=self.s.sign_login(r,'myapp',1000);self.assertTrue(v.verify(response));self.assertFalse(v.verify(response))
 def test_wrong_app(self):
  v=self.verifier();self.assertRaises(ValueError,self.s.sign_login,v.challenge(),'otherapp',1000)
 def test_expired(self):
  v=self.verifier();r=v.challenge();self.assertRaises(ValueError,self.s.sign_login,r,'myapp',1060)
 def test_expired_verifier(self):
  v=self.verifier();r=v.challenge();resp=self.s.sign_login(r,'myapp',1000);v.clock=lambda:1060;self.assertFalse(v.verify(resp))
 def test_tamper(self):
  v=self.verifier();r=v.challenge();resp=self.s.sign_login(r,'myapp',1000);resp['signature']=b64(b'x'*64);self.assertFalse(v.verify(resp))
 def test_action_tamper(self):
  v=self.verifier();r=v.challenge();r['action']='delete';self.assertRaises(ValueError,self.s.sign_login,r,'myapp',1000)
 def test_nonce(self):
  v=self.verifier();r=v.challenge();r['nonce']='bad';self.assertRaises(ValueError,self.s.sign_login,r,'myapp',1000)
 def test_future(self):
  v=self.verifier();r=v.challenge();r['expires']=1061;self.assertRaises(ValueError,self.s.sign_login,r,'myapp',1000)
 def test_unknown(self):self.assertRaises(ValueError,self.s.public_key,'missing')
 def test_idle(self):
  self.clock[0]+=120;self.assertTrue(self.s.is_locked());self.assertRaises(ValueError,self.s.apps)
 def test_locked(self):self.s.lock();self.assertRaises(ValueError,self.s.register,'app')
 def test_corrupt(self):
  self.s.lock();self.path.write_bytes(b'bad');self.assertRaises(ValueError,self.s.unlock,'test-only-password')
 def test_public_enroll_once(self):
  v=self.verifier();self.assertRaises(ValueError,v.enroll,self.s.public_key('myapp'))
 def test_pending_bound(self):
  v=self.verifier()
  for _ in range(100):v.challenge()
  self.assertRaises(ValueError,v.challenge)
 def test_permissions_refusal(self):
  self.s.lock();self.path.chmod(0o644);self.assertRaises(ValueError,self.s.unlock,'test-only-password')
 def test_symlink_refusal(self):
  other=self.path.parent/'link';other.symlink_to(self.path);self.assertRaises(OSError,KeyStore(other).unlock,'test-only-password')
 def test_external_change(self):
  self.path.write_bytes(self.path.read_bytes()+b' ');self.assertRaises(ValueError,self.s.register,'app');self.assertTrue(self.s.is_locked())
 def test_short_password(self):self.assertRaises(ValueError,check_password,'short')
if __name__=='__main__':unittest.main()
