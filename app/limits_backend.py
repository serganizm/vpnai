"""Validated, pinned SSH access for connection limits."""
import json,pathlib
import backend
ROOT=pathlib.Path(__file__).resolve().parent
REMOTE=(ROOT/'limits_remote.py').read_text()+'''\ntry:print(json.dumps({'ok':True,'result':execute(DATA)},ensure_ascii=False))
except Exception as error:print(json.dumps({'ok':False,'error':str(error)},ensure_ascii=False))
'''
def validate(value,inherit=False):
 if inherit and value is None:return None
 if type(value) is not int or not 0<=value<=1000:raise backend.UserError('Количество подключений: 1–1000 или без ограничений.')
 return value
def execute(ep,operation,**data):
 answer=json.loads(ep.python(REMOTE,dict(data,operation=operation)))
 if not isinstance(answer,dict):raise backend.UserError('Некорректный ответ службы лимитов.')
 if not answer.get('ok'):raise backend.UserError(answer.get('error','Не удалось применить лимиты.'))
 return answer['result']
def dispatch(settings,operation,data):
 if operation not in ('limits-status','limits-default','limits-user'):raise backend.UserError('Неизвестная операция лимитов.')
 request={}
 if operation!='limits-status':
  request={'value':validate(data.get('value'),operation=='limits-user'),'revision':data.get('revision',''),'confirmed':data.get('confirmed') is True,'restart_confirmed':data.get('restart_confirmed') is True,'helper':(ROOT/'session_limits.py').read_text()}
  if operation=='limits-user':
   from admin_backend import username
   request['name']=username(data.get('name'))
 ep=backend.Remote('ru',dict(settings['ru']))
 try:
  ep.connect();ep.lock()
  return execute(ep,{'limits-status':'read','limits-default':'default','limits-user':'user'}[operation],**request)
 finally:ep.close()
