# -*- coding: utf-8 -*-
import os
import contextlib,io,json,pathlib,runpy,subprocess,sys,tempfile,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]/'core/payload/ru'
@unittest.skipUnless(os.name=='posix','Server payload execution requires Unix file locking')
class UserComment(unittest.TestCase):
 def run_script(self,source):
  namespace={'__name__':'__main__'}
  try:exec(compile(source,'ovpn-user','exec'),namespace)
  finally:
   if 'lock' in namespace:namespace['lock'].close()
 def test_comment_changes_only_comment(self):
  with tempfile.TemporaryDirectory() as folder:
   root=pathlib.Path(folder);base=root/'server';base.mkdir();db=base/'users.json'
   before={'alice':{'enabled':True,'comment':'old','salt':'salt','hash':'hash'},'other':{'enabled':True}}
   source=(ROOT/'usr/local/sbin/ovpn-user').read_text().replace("'/run/ovpn-user.lock'",repr(str(root/'lock'))).replace("'/etc/openvpn/server'",repr(str(base)))
   for comment in ['новый комментарий','']:
    db.write_text(json.dumps(before))
    with patch.object(sys,'argv',['ovpn-user','comment','alice','--comment',comment]),patch.object(subprocess,'run',side_effect=AssertionError('must not change VPN')),contextlib.redirect_stdout(io.StringIO()):self.run_script(source)
    after=json.loads(db.read_text());expected=json.loads(json.dumps(before));expected['alice']['comment']=comment
    self.assertEqual(after,expected)
   for comment in ['x'*201,'bad\nvalue']:
    db.write_text(json.dumps(before))
    with patch.object(sys,'argv',['ovpn-user','comment','alice','--comment',comment]),self.assertRaises(SystemExit):self.run_script(source)
    self.assertEqual(json.loads(db.read_text()),before)
 def test_menu_order(self):
  module=runpy.run_path(str(ROOT/'usr/local/libexec/ovpn-menu.py'));menu=module['user_menu'];captured=[]
  with patch.dict(menu.__globals__,{'ask':lambda _: '0','option':lambda n,text,red=False:captured.append((n,text,red))}),contextlib.redirect_stdout(io.StringIO()):menu()
  self.assertEqual(captured[2][1],'Изменить/показать пароль');self.assertEqual(captured[3][:2],(4,'Изменить комментарий'));self.assertEqual(captured[5],(6,'Удалить пользователя',True))

 def test_add_if_empty_never_creates_when_any_user_exists(self):
  with tempfile.TemporaryDirectory() as folder:
   root=pathlib.Path(folder);base=root/'server';base.mkdir();db=base/'users.json'
   source=(ROOT/'usr/local/sbin/ovpn-user').read_text().replace("'/run/ovpn-user.lock'",repr(str(root/'lock'))).replace("'/etc/openvpn/server'",repr(str(base)))
   for enabled in (True,False):
    before={'existing':{'enabled':enabled,'comment':'keep'}};db.write_text(json.dumps(before))
    with patch.object(sys,'argv',['ovpn-user','add','newuser','--if-empty']),patch.object(subprocess,'run',side_effect=AssertionError('No creation')),contextlib.redirect_stdout(io.StringIO()):
     with self.assertRaises(SystemExit) as exit:self.run_script(source)
     self.assertEqual(exit.exception.code,0)
    self.assertEqual(json.loads(db.read_text()),before)
