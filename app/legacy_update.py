"""Local adapter for an explicit, bounded update without forged installer ownership."""
import json,pathlib,secrets
import backend
REMOTE=pathlib.Path(__file__).with_name('legacy_update_remote.py').read_text()+'''\ntry:print(json.dumps({'ok':True,'result':execute(DATA)},ensure_ascii=False))
except (ValueError,KeyError) as error:print(json.dumps({'ok':False,'error':str(error)},ensure_ascii=False))
'''
def call(ep,settings,operation,**data):
 answer=json.loads(ep.python(REMOTE,dict(data,operation=operation,ru_ip=settings['ru']['host'],nl_ip=settings['nl']['host'])))
 if not answer.get('ok'):raise backend.UserError(answer.get('error','Не удалось прочитать конфигурацию установленного VPN.'))
 return answer['result']
def read(ep,settings):return call(ep,settings,'read')
def run(job,ru,nl=None):
 s=job.settings;current=read(ru,s)
 if not s.get('update_revision') or not secrets.compare_digest(s['update_revision'],current['revision']):raise backend.UserError('Загрузите актуальные настройки перед изменением входа.')
 c=current['config']
 if s['routing']!=c['routing_mode'] or s['vpn_port']!=c['ovpn_port'] or s['ru_routes']!=current['ru_routes'] or s['eu_routes']!=current['eu_routes'] or s['update_packages']:raise backend.UserError('Для этой установки без переустановки доступна смена способа входа и DNS. Маршруты изменяйте в разделе «Управление»; остальные параметры сохраните текущими.')
 if s.get('legacy_confirmed') is not True:raise backend.UserError('Подтвердите смену входа и переподключение устройств.')
 chosen=None
 if s.get('dns') is not None:
  import dns_backend
  chosen=dns_backend.validate(s['dns'])
  if nl is None:raise backend.UserError('Нет подключения к EU для проверки DNS.')
  if any(ip in (s['ru']['host'],s['nl']['host']) for ip in chosen['servers']):raise backend.UserError('DNS не должен совпадать с адресами VPN-серверов.')
  job.checkpoint();job.event('Проверка DNS',20,'Проверка выбранных DNS с зарубежного сервера до изменения настроек.')
  checked=dns_backend.execute(nl,'probe',servers=chosen['servers']) if chosen['servers'] else {'passed':True}
  if not checked['passed']:raise backend.UserError('DNS недоступен с EU по UDP или TCP 53. Настройки не изменены.')
 job.checkpoint();job.event('Смена входа',30,'Резервная копия настроек и профилей; сертификаты, пользователи, DNS и туннель сохраняются. Активные подключения прервутся.')
 result=call(ru,s,'apply',auth=s['auth'],revision=current['revision'],confirmed=s['legacy_confirmed'])
 job.report.update(legacy=True,auth=s['auth'],routing=c['routing_mode'],users_preserved=current['user_count'],authentication_update=result,notice='Способ входа обновлён. Пользователи, сертификаты, DNS и маршруты сохранены. Импортируйте обновлённые профили и переподключите устройства.' if not result.get('unchanged') else 'Способ входа уже соответствует выбранному; сервер не изменён.')
 dns_error=None
 if chosen is not None:
  try:
   job.checkpoint();job.event('Применение DNS',75,'Применение выбранных DNS с отдельной резервной копией. OpenVPN будет перезапущен.')
   status=dns_backend.execute(ru,'read')
   applied=dns_backend.execute(ru,'apply',**chosen,revision=status['revision'],peer=s['nl']['host'],helper=(dns_backend.ROOT/'dns_policy.py').read_text(),unit=dns_backend.UNIT)
   job.report['dns']=dict(applied,applied=True)
   job.report['notice']=('Способ входа обновлён. ' if not result.get('unchanged') else 'Способ входа сохранён. ')+'Выбранные DNS применены. Пользователи, сертификаты и маршруты сохранены. Переподключите устройства; при смене входа импортируйте обновлённые профили.'
  except backend.UserError as error:
   dns_error=str(error);job.report['dns']={'applied':None,'error':dns_error}
   job.report['notice']=('Способ входа обновлён, ' if not result.get('unchanged') else 'Способ входа сохранён, ')+'а DNS требует проверки. '+dns_error+' Перечитайте настройки перед повторением.'
 try:
  job.artifact=backend.collect(ru);job.expires=backend.time.time()+600
 except backend.UserError:
  job.report['notice']+=' Архив сейчас недоступен; скачайте профили в разделе «Управление». '
 if dns_error:raise backend.UserError(job.report['notice'])
 job.event('Готово',100,job.report['notice'])
