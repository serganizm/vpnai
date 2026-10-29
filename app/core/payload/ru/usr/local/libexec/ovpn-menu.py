#!/usr/bin/python3
import pathlib,subprocess,json,socket,getpass,os,sys,collections
DB=pathlib.Path('/etc/openvpn/server/users.json');OUT=pathlib.Path('/root/ovpn-profiles')
COLOR=sys.stdout.isatty() and os.environ.get('TERM','')!='dumb'
def color(text,code):return f'\033[{code}m{text}\033[0m' if COLOR else str(text)
def label(s):return color(s,'38;2;203;166;247')
def value(s):return color(s,'38;2;166;226;158')
def number(s):return color(s,'38;2;137;220;235')
def danger(s):return color(s,'91')
def muted(s):return color(s,'38;2;156;155;176')
def good(s):return color(s,'92')
def ask(prompt):return input(number(prompt) if prompt.startswith('Выберите действие:') else label(prompt))
def space():print('\n')
def heading(text,red=False):
 line=muted('='*(len(text)+6))
 print(line);print('   '+number(text));print(line);print()
def option(n,text,red=False):print(f'  {number("["+str(n)+"]")} {(danger if red else label)(text)}')
def users():return json.loads(DB.read_text())
def sessions():
 rows=[];errors=[];connected=0
 for protocol,path in [('UDP','/run/openvpn-server/ru-management.sock'),('TCP','/run/openvpn-server/ru-tcp-management.sock')]:
  conn=socket.socket(socket.AF_UNIX);conn.settimeout(3)
  try:
   conn.connect(path);conn.recv(4096);conn.sendall(b'status 3\n');data=''
   while '\nEND' not in data:
    part=conn.recv(65536)
    if not part:break
    data+=part.decode(errors='replace')
   rows.extend([line.rstrip('\r').split('\t')+[protocol] for line in data.splitlines() if line.startswith('CLIENT_LIST\t') and len(line.split('\t'))>=7]);connected+=1
  except OSError as e:errors.append(e)
  finally:conn.close()
 if not connected and errors:raise errors[0]
 return rows
def size(raw):
 try:n=float(raw)
 except ValueError:return raw+' Б'
 for unit in ('Б','КиБ','МиБ','ГиБ','ТиБ'):
  if n<1024 or unit=='ТиБ':return f'{n:.1f} {unit}' if unit!='Б' else f'{int(n)} Б'
  n/=1024
def peer_address(raw):
 text=raw
 for prefix in ('udp4:', 'udp6:', 'tcp4:', 'tcp6:', 'tcp4-server:', 'tcp6-server:'):
  if text.startswith(prefix):text=text[len(prefix):];break
 if text.startswith('[') and ']:' in text:
  ip,port=text[1:].rsplit(']:',1)
 elif ':' in text:
  ip,port=text.rsplit(':',1)
 else:ip,port=text,''
 return ip,port
def listing(active=False):
 data=users();rows=[];available=True
 if active:
  try:rows=sessions()
  except OSError as e:print(danger('Не удалось получить активные сессии: ')+value(e));available=False
 counts=collections.Counter(r[1] for r in rows)
 heading('АКТИВНЫЕ ПОЛЬЗОВАТЕЛИ')
 visible={n:v for n,v in data.items() if not v.get('deleted')}
 if not visible:print(muted('  Пользователей нет.'))
 name_width=max([len('Пользователь')]+[len(n) for n in visible])
 status_width=max([len('Статус')]+[len('активен' if v.get('enabled') else 'доступ отозван') for v in visible.values()])
 connection_width=max([len('Подключений')]+[len(str(counts[n])) for n in visible])
 sep='  '+muted('│')+'  '
 header='  '+label('Пользователь'.ljust(name_width))+sep+label('Статус'.ljust(status_width))
 if active and available:header+=sep+label('Подключений'.rjust(connection_width))
 header+=sep+label('Комментарий')
 if visible:print(header)
 for n,v in sorted(visible.items()):
  status_text='активен' if v.get('enabled') else 'доступ отозван'
  status=(good if v.get('enabled') else danger)(status_text.ljust(status_width))
  row='  '+number(n.ljust(name_width))+sep+status
  if active and available:row+=sep+number(str(counts[n]).rjust(connection_width))
  row+=sep+value(v.get('comment','') or '—')
  print(row)
 if active:
  space();heading('АКТИВНЫЕ ПОДКЛЮЧЕНИЯ')
  print(muted('Данные в реальном времени; трафик — со стороны сервера.'))
  if available and not rows:print(muted('  Нет подключений.'))
  for i,r in enumerate(rows,1):
   print(f'\n  {number("["+str(i)+"]")} {number(r[1])}')
   peer_ip,peer_port=peer_address(r[2])
   print('     '+label('IP клиента:')+' '+value(peer_ip)+muted(' ('+r[-1]+')'))
   if peer_port:print(f'     {label("Порт клиента:")} {number(peer_port)}')
   print(f'     {label("VPN-адрес:")} {value(r[3])}')
   print(f'     {label("Протокол:")} {number(r[-1])}')
   print(f'     {label("Принято:")} {number(size(r[5]))}   {label("Отправлено:")} {number(size(r[6]))}')
def choose_user():
 names=sorted(n for n,v in users().items() if v.get('enabled') and not v.get('deleted'))
 if not names:print(muted('Нет активных пользователей.'));return None
 for i,n in enumerate(names,1):print(f'  {number("["+str(i)+"]")} {value(n)}')
 print();print(muted('  [0] — вернуться назад'))
 while True:
  a=ask('Номер пользователя: ').strip()
  if a in ('','0'):return None
  if a.isdigit() and 1<=int(a)<=len(names):space();return names[int(a)-1]
  print(danger('Выберите номер из списка.'))
def run(*args,password=None):
 r=subprocess.run(['/usr/local/sbin/ovpn-user',*args],input=password,text=True,capture_output=True)
 if r.returncode:print(danger('Ошибка: ')+value(r.stderr.strip() or r.stdout.strip()));return False
 print(good('Готово.'))
 return True
def credentials(name):
 p=OUT/(name+'-credentials.txt');print()
 if p.exists():
  for line in p.read_text().splitlines():
   if line.startswith('Login: '):print(label('Логин: ')+value(line[7:]))
   elif line.startswith('Password: '):print(label('Пароль: ')+value(line[10:]))
 print(label('UDP: ')+value(OUT/(name+'-UDP.ovpn')))
 print(label('TCP: ')+value(OUT/(name+'-TCP.ovpn')))
def confirm_delete(name):
 print(danger('Будут отозваны сертификат и доступ, удалены профиль и файл пароля.'))
 print(label('Имя можно создать заново с новым профилем и паролем.'))
 print(muted('Старый сертификат останется отозванным.'));print()
 answer=ask(f'Для удаления введите логин {name} ([0] или Enter — отмена): ').strip()
 if answer!=name:print(muted('Удаление отменено.'));return False
 return True
def pause():
 while ask('\n[0] или Enter — назад: ').strip() not in ('','0'):print(muted('Нажмите [0] или Enter.'))
def password_qr(name):
 import hashlib,hmac
 p=OUT/(name+'-credentials.txt')
 if not p.is_file():
  print(danger('Сохранённого пароля нет. Задайте или сгенерируйте новый пароль.'));return
 password=next((l[len('Password: '):] for l in p.read_text().splitlines() if l.startswith('Password: ')),None)
 record=users().get(name,{})
 try:valid=password is not None and hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(record['salt']),300000).hex(),record['hash'])
 except (KeyError,ValueError):valid=False
 if not valid:print(danger('Сохранённый пароль не совпадает с действующим. Задайте новый пароль.'));return
 print(label('Логин: ')+value(name));print(label('Пароль: ')+value(password));print()
 try:
  import qrcode
  qr=qrcode.QRCode(border=2,error_correction=qrcode.constants.ERROR_CORRECT_L);qr.add_data(password);qr.make(fit=True);qr.print_ascii(invert=True)
  print(muted('QR-код содержит только пароль. Отсканируйте и скопируйте его.'))
 except ImportError:print(muted('QR-код недоступен; используйте пароль выше.'))
def password_menu():
 while True:
  space();heading('ПАРОЛЬ ПОЛЬЗОВАТЕЛЯ')
  option(1,'Задать пароль');option(2,'Сгенерировать пароль');option(3,'Показать пароль и QR-код');option(0,'Назад');print()
  mode=ask('Выберите действие: ').strip();space()
  if mode in ('','0'):return
  if mode not in ('1','2','3'):print(danger('Неизвестный пункт.'));continue
  name=choose_user()
  if name is None:continue
  if mode=='3':password_qr(name)
  elif mode=='2':
   if run('passwd',name,'--auto'):credentials(name)
  else:
   p=getpass.getpass(label('Новый пароль (не менее 8 символов; [0] или Enter — назад): '))
   if p in ('','0'):continue
   if p!=getpass.getpass(label('Повторите пароль: ')):print(danger('Пароли не совпадают.'))
   elif run('passwd',name,password=p+'\n'):print(good('Пароль изменён. Переподключите устройства с новым паролем.'))
  pause()
def user_menu():
 while True:
  space();heading('ПОЛЬЗОВАТЕЛИ')
  for n,t in [(1,'Пользователи и подключения'),(2,'Новый пользователь'),(3,'Изменить/показать пароль'),(4,'Конфигурационные файлы'),(5,'Удалить пользователя'),(0,'Назад')]:option(n,t,n==5)
  print();a=ask('Выберите действие: ').strip();space()
  if a in ('','0'):return
  if a=='1':listing(True)
  elif a=='2':
   heading('НОВЫЙ ПОЛЬЗОВАТЕЛЬ')
   name=ask('Новый логин ([0] или Enter — назад): ').strip()
   if name in ('','0'):continue
   comment=ask('Комментарий (Enter — без комментария): ').strip()
   if run('add',name,'--comment',comment):credentials(name)
  elif a=='3':password_menu();continue
  elif a=='4':download_menu();continue
  elif a=='5':
   heading('УДАЛЕНИЕ',red=True);name=choose_user()
   if name is None:continue
   if confirm_delete(name):run('delete',name)
  else:print(danger('Неизвестный пункт.'));continue
  pause()

def manual_entries(kind='ru'):
 args=['/usr/local/sbin/ovpn-custom']+(['--nl'] if kind=='nl' else [])+['list']
 r=subprocess.run(args,capture_output=True,text=True)
 if r.returncode:raise RuntimeError(r.stderr.strip())
 return json.loads(r.stdout)
def show_routes(kind='ru'):
 import shutil,tempfile
 heading('RU-EU' if kind=='nl' else 'RU')
 items=manual_entries(kind)
 text=muted('Выход через зарубежный сервер.' if kind=='nl' else 'Выход через российский сервер. Приоритет над списками RU-EU.')+'\n\n'
 text+='\n'.join(f'  {number("["+str(i)+"]")} {value(item)}' for i,item in enumerate(items,1)) if items else muted('Список пуст.')
 print(muted('Просмотр: стрелки / PageUp / PageDown; [0] или Enter — назад.'))
 if sys.stdout.isatty() and shutil.which('less'):
  with tempfile.NamedTemporaryFile(mode='w',prefix='ovpn-less-') as keys:
   keys.write('#command\n\\r quit\n\\n quit\n0 quit\n');keys.flush()
   subprocess.run(['less','-R','--lesskey-src='+keys.name],input=text+'\n',text=True,env=dict(os.environ,LESSKEYIN=keys.name,LESSKEY=os.devnull))
 else:print(text)
 return items
def custom_change(cmd,item,kind='ru'):
 args=['/usr/local/sbin/ovpn-custom']+(['--nl'] if kind=='nl' else [])+[cmd,item]
 r=subprocess.run(args,capture_output=True,text=True)
 if r.returncode:print(danger('Ошибка: ')+value(r.stderr.strip()));return False
 print(good('Добавлено: ' if cmd=='add' else 'Удалено: ')+value(r.stdout.strip()))
 print(muted('Для получения новых маршрутов переподключите VPN.'));return True
def routes_menu(kind='ru'):
 while True:
  space();heading('RU-EU' if kind=='nl' else 'RU')
  print(muted('Просмотр: стрелки / PageUp / PageDown; [0] или Enter — назад.'));print()
  option(1,'Показать список');option(2,'Добавить IP');option(3,'Удалить IP',True);option(0,'Назад');print()
  a=ask('Выберите действие: ').strip();space()
  if a in ('','0'):return
  if a=='1':show_routes(kind);continue
  elif a=='2':
   heading('ДОБАВЛЕНИЕ IP');item=ask('Публичный IPv4 или CIDR ([0] или Enter — назад): ').strip()
   if item in ('','0'):continue
   custom_change('add',item,kind)
  elif a=='3':
   heading('УДАЛЕНИЕ IP',red=True);items=manual_entries(kind)
   if not items:print(muted('Список пуст.'));pause();continue
   for i,item in enumerate(items,1):print(f'  {number("["+str(i)+"]")} {value(item)}')
   choice=ask('Номер записи ([0] или Enter — назад): ').strip()
   if choice in ('','0'):continue
   if not choice.isdigit() or not 1<=int(choice)<=len(items):print(danger('Неверный номер.'));pause();continue
   item=items[int(choice)-1];print(danger('Удалить: ')+value(item))
   print(muted('Другие списки сохраняются. Итоговый путь зависит от оставшихся записей.'))
   if ask('[1] — подтвердить; [0] или Enter — отмена: ').strip()=='1':custom_change('remove',item,kind)
   else:print(muted('Удаление отменено.'))
  else:print(danger('Неизвестный пункт.'));continue
  pause()
def routing_menu():
 while True:
  space();heading('МАРШРУТИЗАЦИЯ')
  option(1,'RU-EU IPList');option(2,'RU-EU');option(3,'RU');option(0,'Назад');print()
  choice=ask('Выберите действие: ').strip();space()
  if choice in ('','0'):return
  if choice=='1':iplist_menu()
  elif choice=='2':routes_menu('nl')
  elif choice=='3':routes_menu('ru')
  else:print(danger('Неизвестный пункт.'))
def iplist_show():
 import ipaddress,shutil
 heading('RU-EU IPLIST')
 path=pathlib.Path('/var/lib/ovpn-routing/source.json')
 if not path.exists():print(muted('Список ещё не загружен. Выберите обновление списка.'));return
 items=sorted(set(json.loads(path.read_text())),key=lambda x:(int(ipaddress.ip_network(x).network_address),ipaddress.ip_network(x).prefixlen))
 text=label('CIDR из IPList: ')+number(len(items))+'\n'+muted('Ручные записи из раздела «Свои маршруты» сюда не включены.')+'\n\n'
 text+='\n'.join(f'  {number("["+str(i)+"]")} {value(item)}' for i,item in enumerate(items,1))
 if sys.stdout.isatty() and shutil.which('less'):
  print(muted('Просмотр: стрелки / PageUp / PageDown; [0] или Enter — назад.'))
  import tempfile,os
  # lesskey's legacy source format: bind both terminal Enter encodings to quit.
  with tempfile.NamedTemporaryFile(mode='w',prefix='ovpn-less-',delete=True) as keys:
   keys.write('#command\n\\r quit\n\\n quit\n0 quit\n');keys.flush()
   env=dict(os.environ,LESSKEYIN=keys.name,LESSKEY=os.devnull)
   subprocess.run(['less','-R','--lesskey-src='+keys.name],input=text+'\n',text=True,env=env)
 else:print(text)
def iplist_update():
 heading('ОБНОВЛЕНИЕ IPLIST')
 print(label('Загрузка и проверка CIDR с сайта IPList…'))
 r=subprocess.run(['/usr/local/sbin/ovpn-routing','update'],capture_output=True,text=True)
 if r.returncode:
  print(danger('Обновление не выполнено. Проверьте источник и повторите попытку.'))
  print(muted(r.stderr.strip() or r.stdout.strip()));return
 data=json.loads(r.stdout)
 print(good('Список обновлён и применён.'))
 print(label('CIDR: ')+number(data.get('source_cidr_count',0)))
 print(label('Сервисов: ')+number(data.get('portals',0)))
 print(muted('Свои маршруты сохранены. Для получения новых маршрутов переподключите VPN.'))
def iplist_menu():
 while True:
  space();heading('RU-EU IPLIST')
  print(muted('Просмотр: стрелки / PageUp / PageDown; [0] или Enter — назад.'));print()
  option(1,'Показать список');option(2,'Обновить список с сайта');option(0,'Назад');print()
  a=ask('Выберите действие: ').strip();space()
  if a in ('','0'):return
  if a=='1':iplist_show();continue
  elif a=='2':iplist_update()
  else:print(danger('Неизвестный пункт.'));continue
  pause()

def download_candidates():
 return sorted(n for n,v in users().items() if v.get('enabled') and not v.get('deleted') and (OUT/(n+'.ovpn')).is_file())
def prepare_download(names,all_users=False):
 import zipfile,tempfile,fcntl,re
 folder=pathlib.Path('/root/ovpn-downloads');folder.mkdir(mode=0o700,exist_ok=True);folder.chmod(0o700)
 with open('/run/ovpn-user.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_SH)
  current=download_candidates()
  selected=current if all_users else [n for n in names if n in current]
  if not selected:raise ValueError('Нет доступных профилей для скачивания.')
  if any(not re.fullmatch('[a-zA-Z0-9_-]{1,48}',n) for n in selected):raise ValueError('Недопустимое имя профиля.')
  filename='IPSRU-all.zip' if all_users else 'IPSRU-'+selected[0]+'.zip'
  target=folder/filename
  fd,tmp=tempfile.mkstemp(prefix='.export-',dir=folder);os.close(fd)
  try:
   with zipfile.ZipFile(tmp,'w',compression=zipfile.ZIP_DEFLATED) as z:
    for name in selected:
     variants=('-UDP.ovpn','-TCP.ovpn') if all((OUT/(name+x)).is_file() for x in ('-UDP.ovpn','-TCP.ovpn')) else ('.ovpn',)
     for suffix in variants+('-credentials.txt',):
      f=OUT/(name+suffix)
      if f.is_file():z.write(f,arcname=f.name)
   os.chmod(tmp,0o600);os.replace(tmp,target)
  finally:
   if os.path.exists(tmp):os.unlink(tmp)
 return target,len(selected)
def download_link_menu(selected,all_users=False):
 import datetime
 from zoneinfo import ZoneInfo
 space();heading('СКАЧАТЬ ПО ССЫЛКЕ')
 args=['/usr/local/sbin/ovpn-link','create-all'] if all_users else ['/usr/local/sbin/ovpn-link','create',selected[0]]
 r=subprocess.run(args,capture_output=True,text=True)
 if r.returncode:print(danger('Не удалось создать ссылку: ')+value(r.stderr.strip()));pause();return
 data=json.loads(r.stdout);space();heading('ССЫЛКА ГОТОВА')
 print(label('Пользователей в архиве: ')+number(data['count']))
 expiry=datetime.datetime.fromtimestamp(data['expires'],ZoneInfo('Europe/Moscow')).strftime('%H:%M:%S')
 print(label('Действует 10 минут, до ')+number(expiry)+label(' МСК.'))
 print(muted('Можно скачивать несколько раз на разные устройства до истечения срока.'))
 print(muted('ZIP содержит .ovpn и файл с логином и паролем.'));print()
 print(value(data['url']));print()
 try:
  import qrcode
  qr=qrcode.QRCode(border=2,error_correction=qrcode.constants.ERROR_CORRECT_L);qr.add_data(data['url']);qr.make(fit=True);qr.print_ascii(invert=True)
 except ImportError:print(muted('QR-код недоступен; используйте ссылку выше.'))
 print(label('Откройте ссылку в браузере или отсканируйте QR-код.'))
 print(muted('Распакуйте ZIP и импортируйте .ovpn в OpenVPN Connect.'))
 pause()

def download_menu():
 while True:
  space();heading('КОНФИГУРАЦИОННЫЕ ФАЙЛЫ')
  print(muted('Архив включает профили .ovpn и сохранённые логины/пароли.'));print()
  print(f'  {number("[1]")} {value("ВСЕ КОНФИГУРАЦИИ")}')
  names=download_candidates()
  for i,name in enumerate(names,2):print(f'  {number("["+str(i)+"]")} {value(name)}')
  option(0,'Назад');print()
  a=ask('Выберите действие: ').strip();space()
  if a in ('','0'):return
  if not a.isdigit() or not 1<=int(a)<=len(names)+1:print(danger('Неверный номер.'));continue
  all_users=a=='1';selected=names if all_users else [names[int(a)-2]]
  heading('СПОСОБ СКАЧИВАНИЯ')
  option(1,'Скачать по ссылке');option(2,'macOS');option(3,'Linux');option(4,'Windows (PowerShell)');option(0,'Назад');print()
  system=ask('Выберите действие: ').strip();space()
  if system in ('','0'):continue
  if system=='1':download_link_menu(selected,all_users);continue
  if system not in ('2','3','4'):print(danger('Неверный номер.'));continue
  try:path,count=prepare_download(selected,all_users)
  except Exception as e:print(danger('Не удалось подготовить архив: ')+value(e));pause();continue
  remote='root@@@RU_IP@@:'+str(path)
  heading('АРХИВ ГОТОВ')
  print(label('Пользователей в архиве: ')+number(count))
  print(label('Файл: ')+value(path.name));print()
  print(label('Выполните следующую команду НА СВОЁМ КОМПЬЮТЕРЕ.'))
  print(muted('Откройте отдельное окно терминала, не вводите команду внутри SSH.'));print()
  if system=='2':
   command=f'scp {remote} "$HOME/Downloads/"'
  elif system=='3':
   command=f'scp {remote} ~/Downloads/'
  else:
   command=f'scp {remote} "$HOME\\Downloads\\"'
  print(value(command));print()
  print(muted('scp запросит SSH-доступ к серверу, а не пароль пользователя OpenVPN.'))
  print(label('После скачивания распакуйте ZIP и импортируйте .ovpn в OpenVPN Connect.'))
  pause()

def main():
 if os.geteuid()!=0:sys.exit('Запустите от root: sudo /root/menu.sh')
 while True:
  space();heading('OpenVPN')
  option(1,'Пользователи');option(2,'Маршрутизация');option(0,'Выход');print()
  a=ask('Выберите действие: ').strip();space()
  if a in ('','0'):print(muted('Выход.'));return
  if a=='1':user_menu()
  elif a=='2':routing_menu()
  else:print(danger('Неизвестный пункт.'))
if __name__=='__main__':
 try:main()
 except (KeyboardInterrupt,EOFError):print('\n'+muted('Выход.'))
 except Exception as e:sys.exit('Ошибка: '+str(e))
