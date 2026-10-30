'use strict';
const $=id=>document.getElementById(id);
let token=location.hash.slice(1)||sessionStorage.getItem('vpn-local-token')||'';
if(location.hash){sessionStorage.setItem('vpn-local-token',token);history.replaceState(null,'',location.pathname);}
let page=0,selected={action:'install',routing:'split',auth:'password'},pins={},jobId=sessionStorage.getItem('vpn-job')||'',pollTimer=null,running=false,sshAvailable=false,platform='macos';
const actionNames={check:'Проверить серверы',install:'Установить',resume:'Восстановить',verify:'Проверить VPN',fresh:'Установить заново',remove:'Удалить установку'};
const routeNames={split:'Раздельные маршруты',full_mixed:'Весь трафик через VPN',full_nl:'Весь трафик через зарубежный сервер'};
const authNames={password:'Сертификат + логин и пароль',certificate:'Только индивидуальный сертификат'};
function message(text){$('error').textContent=text;$('error').classList.toggle('hidden',!text);if(text)$('error').scrollIntoView({behavior:'smooth',block:'center'});}
function choiceGroup(target,key,items){
 const box=$(target);box.replaceChildren();
 for(const [value,title,description] of items){const b=document.createElement('button');b.type='button';b.className='choice'+(selected[key]===value?' selected':'');b.setAttribute('aria-pressed',selected[key]===value);const strong=document.createElement('strong');strong.textContent=title;const p=document.createElement('p');p.textContent=description;b.append(strong,p);b.onclick=()=>{if(running)return;selected[key]=value;choiceGroup(target,key,items);updateRouteNotice();};box.append(b);}
}
function serverCard(role,title,tag){
 return `<div class="panel"><div class="panel-top"><span class="tag ${role==='nl'?'green':''}">${tag}</span><span class="muted">SSH</span></div><h2>${title}</h2><div class="fields"><div class="input-row"><label>IP-адрес<input id="${role}Host" placeholder="Публичный IPv4" autocomplete="off"></label><label>SSH-порт<input id="${role}Port" type="number" min="1" max="65535" value="22"></label></div><label>Пользователь<input id="${role}User" value="root" readonly></label><label>Способ подключения<select id="${role}Method"><option value="password">Пароль</option><option value="key">Вставить приватный SSH-ключ</option><option value="local-key">Мой локальный ключ / скопировать на сервер</option></select></label><label id="${role}PasswordRow">Пароль SSH<input id="${role}Password" type="password" autocomplete="off" placeholder="Не сохраняется"></label><div id="${role}KeyRow" class="hidden"><label>Содержимое приватного SSH-ключа<textarea id="${role}Key" spellcheck="false" placeholder="Вставьте приватный ключ" autocomplete="off"></textarea></label><label>Пароль ключа <small>если задан</small><input id="${role}Passphrase" type="password" autocomplete="off"></label></div><div id="${role}LocalRow" class="hidden local-key-box"><label>Путь к приватному ключу на этом компьютере<input id="${role}KeyPath" value="~/.ssh/id_ed25519" autocomplete="off"></label><label>Пароль ключа <small>если задан</small><input id="${role}LocalPassphrase" type="password" autocomplete="off"></label><p>Если публичный ключ ещё не установлен на сервере, скопируйте команду и выполните её на своём компьютере. SSH запросит пароль сервера.</p><div class="key-actions"><label>Система для команды<select id="${role}CommandOS"><option value="macos">macOS</option><option value="linux">Linux</option><option value="windows">Windows · PowerShell</option></select></label><button id="${role}MakeCommand" type="button" class="secondary">Показать команду</button></div><pre id="${role}CopyCommand" class="hidden key-command"></pre><button id="${role}CopyButton" type="button" class="secondary hidden">Скопировать команду</button><details id="${role}Fallback" class="hidden"><summary>Если ssh-copy-id не установлен</summary><pre id="${role}FallbackCommand" class="key-command"></pre><button id="${role}FallbackCopy" type="button" class="secondary">Скопировать альтернативу</button></details><p>На сервер копируется только публичный файл .pub. Для подключения приложение прочитает приватный ключ локально, не загружая его на сервер.</p></div></div></div>`;
}
$('serverCards').innerHTML=serverCard('ru','Российский сервер','RU')+serverCard('nl','Зарубежный сервер','EU');
choiceGroup('actions','action',[
 ['check','Проверить серверы','Только прочитать состояние'],['install','Установить','Новая установка на двух серверах'],['resume','Восстановить','Сохранить пользователей и списки'],['verify','Проверить VPN','Службы, туннель и маршруты'],['fresh','Установить заново','Сбросить свою установку'],['remove','Удалить установку','Только компоненты установщика']]);
choiceGroup('routes','routing',[
 ['split','Раздельные маршруты','IPList и RU-EU → зарубежный сервер. RU → российский. Остальные IPv4 → напрямую.'],
 ['full_mixed','Весь трафик через VPN','IPList и RU-EU → зарубежный сервер. RU и остальные IPv4 → российский.'],
 ['full_nl','Весь трафик через зарубежный сервер','Все внешние IPv4 → российский сервер → зарубежный сервер. Ручные списки не влияют на выход.']]);
choiceGroup('authChoices','auth',[
 ['password','Сертификат + пароль','Индивидуальный профиль, логин и пароль пользователя.'],['certificate','Только сертификат','Индивидуальный файл без ввода логина и пароля. Его копия даёт доступ к VPN.']]);
function updateRouteNotice(){
 if(!$('routeNotice'))return;
 $('routeNotice').textContent=selected.routing==='split'?'IPList загружается с сайта автоматически. Остальные IPv4 идут напрямую. DNS и IPv6 устройства остаются без изменений; IPv6 может обходить эти списки.':selected.routing==='full_mixed'?'Все IPv4 идут в VPN. IPList и ручной RU-EU выходят через зарубежный сервер, остальные — через российский. IPv6 и DNS-настройки устройства не меняются.':'Все внешние IPv4 выходят через зарубежный сервер. Ручные списки сохраняются, но в этом режиме на выход не влияют. IPv6 и DNS-настройки устройства не меняются.';
}
function invalidatePins(){pins={};$('sshTrustStatus').textContent='SSH-ключи будут автоматически проверены при запуске операции. Для новых серверов потребуется подтверждение доверия.';}
for(const role of ['ru','nl']){
 $(role+'Method').onchange=()=>{const key=$(role+'Method').value==='key';$(role+'KeyRow').classList.toggle('hidden',!key);$(role+'LocalRow').classList.toggle('hidden',$(role+'Method').value!=='local-key');$(role+'PasswordRow').classList.toggle('hidden',$(role+'Method').value!=='password');invalidatePins();};
 for(const field of ['Host','Port','KeyPath'])$(role+field).addEventListener('input',()=>{invalidatePins();clearCommand(role);});
 $(role+'CommandOS').onchange=()=>clearCommand(role);
 $(role+'MakeCommand').onclick=()=>makeCommand(role);
 $(role+'CopyButton').onclick=()=>copyCommand(role,false);
 $(role+'FallbackCopy').onclick=()=>copyCommand(role,true);
}
function applyMode(){const demo=$('demo').checked;$('modeBadge').textContent=demo?'ДЕМОНСТРАЦИЯ':'РЕАЛЬНЫЕ СЕРВЕРЫ';$('realNotes').classList.toggle('hidden',demo);document.querySelector('.demo-options').classList.toggle('hidden',!demo);$('sshMissing').classList.toggle('hidden',sshAvailable);invalidatePins();if(page===3)review();}
$('demo').onchange=applyMode;
for(const [id,countId] of [['ruRoutes','ruCount'],['euRoutes','euCount']])$(id).oninput=()=>{$(countId).textContent=$(id).value.split('\n').filter(x=>x.split('#')[0].trim()).length+' записей';};
function data(){
 const d={demo:$('demo').checked,action:selected.action,routing:selected.routing,auth:selected.auth,initial_user:$('initialUser').value,comment:$('comment').value,vpn_port:$('vpnPort').value,update_packages:$('updatePackages').value==='yes',ru_routes:$('ruRoutes').value,eu_routes:$('euRoutes').value,scenario:$('scenario').value,confirmation:$('confirmation').value};
 for(const role of ['ru','nl'])d[role]={host:$(role+'Host').value,port:$(role+'Port').value,user:'root',method:$(role+'Method').value,password:$(role+'Password').value,key:$(role+'Key').value,key_path:$(role+'KeyPath').value,passphrase:$(role+($(role+'Method').value==='local-key'?'LocalPassphrase':'Passphrase')).value,fingerprint:pins[role]||''};return d;
}
async function api(path,payload){const options={headers:{'X-Local-Token':token}};if(payload!==undefined){options.method='POST';options.headers['Content-Type']='application/json';options.body=JSON.stringify(payload);}const r=await fetch(path,options);const answer=await r.json();if(!r.ok)throw Error(answer.error||'Ошибка запроса.');return answer;}
function show(n){if(running&&n!==3)return;page=n;message('');document.querySelectorAll('.page').forEach(el=>el.classList.toggle('hidden',Number(el.dataset.page)!==n));document.querySelectorAll('.nav').forEach(el=>el.classList.toggle('active',Number(el.dataset.page)===n));if(n===3)review();window.scrollTo({top:0,behavior:'smooth'});}
document.querySelectorAll('.nav').forEach(b=>b.onclick=()=>show(Number(b.dataset.page)));
document.querySelectorAll('.next').forEach(b=>b.onclick=()=>show(Math.min(3,page+1)));
document.querySelectorAll('.back').forEach(b=>b.onclick=()=>show(Math.max(0,page-1)));
function review(){const d=data();const rows=[['Российский сервер',d.ru.host||(d.demo?'Пример · 198.51.100.10':'Не указан')],['Зарубежный сервер',d.nl.host||(d.demo?'Пример · 203.0.113.20':'Не указан')],['Действие',actionNames[d.action]],['Маршрутизация',routeNames[d.routing]],['Авторизация',authNames[d.auth]],['Обновить пакеты ОС',d.update_packages?'Да':'Нет'],['Пользователь',d.initial_user],['Список RU',d.ru_routes.split('\n').filter(x=>x.split('#')[0].trim()).length+' записей'],['Список RU-EU',d.eu_routes.split('\n').filter(x=>x.split('#')[0].trim()).length+' записей']];$('summary').replaceChildren();for(const [title,value] of rows){const item=document.createElement('div');item.className='summary-item';const k=document.createElement('small');k.textContent=title;const v=document.createElement('strong');v.textContent=value;item.append(k,v);$('summary').append(item);}$('destructive').classList.toggle('hidden',!['fresh','remove'].includes(d.action));$('start').textContent=d.demo?'Запустить демонстрацию →':actionNames[d.action]+' →';$('reviewSubtitle').textContent=d.demo?'Демонстрация не создаёт соединений и ничего не меняет на серверах.':'Будут использованы только два указанных сервера. Пароли не записываются в файлы.';}

function lockForm(lock){running=lock;document.querySelectorAll('input,select,textarea,.choice,.nav').forEach(el=>el.disabled=lock);$('runControls').classList.toggle('hidden',lock||!!jobId);}
async function prepareSSH(d){
 const prepared=await api('/api/ssh/prepare',d);
 if(prepared.confirmation_required){
  const unknown=prepared.servers.filter(s=>!s.known);
  const description=unknown.map(s=>(s.role==='ru'?'Российский':'Зарубежный')+' сервер '+s.host+':'+s.port+'\n'+s.fingerprint).join('\n\n');
  const accepted=window.confirm('Первое подключение: доверять этим SSH-ключам?\n\n'+description+'\n\nПри возможности сверьте отпечатки через консоль хостинга. Без независимой сверки первое подключение основано на доверии полученному ключу. Пароль пока не передавался.\n\nОК — сохранить ключи на этом компьютере и продолжить; Отмена — остановиться.');
  if(!accepted){message('Подключение отменено. Новые SSH-ключи не сохранены, пароль серверам не передавался.');return false;}
  pins=(await api('/api/ssh/confirm',{confirmation_token:prepared.confirmation_token,accept:true})).fingerprints;
 }else pins=prepared.fingerprints;
 for(const role of ['ru','nl'])d[role].fingerprint=pins[role];
 $('sshTrustStatus').textContent='SSH-ключи проверены. При соединении они будут проверены повторно.';
 return true;
}
$('start').onclick=async()=>{
 message('');const d=data();lockForm(true);$('start').disabled=true;
 try{
  if(!d.demo&&!(await prepareSSH(d)))return;
  const j=await api('/api/jobs',d);jobId=j.id;sessionStorage.setItem('vpn-job',jobId);
  for(const r of ['ru','nl'])for(const suffix of ['Password','Key','Passphrase','LocalPassphrase'])$(r+suffix).value='';
  $('progressPanel').classList.remove('hidden');$('result').classList.add('hidden');poll();
 }catch(e){message(e.message);}
 finally{if(!jobId)lockForm(false);$('start').disabled=false;}
};

function reportSummary(r){
 if(!r.servers)return;
 const rows=[['Российский сервер',r.servers.ru],['Зарубежный сервер',r.servers.nl],['Действие',actionNames[r.action]],['Маршрутизация',(routeNames[r.routing]||'Не определена — см. журнал')],['Авторизация',(authNames[r.auth]||'Не определена — см. журнал')],['Обновить пакеты ОС',r.update_packages?'Да':'Нет'],['Пользователь',r.initial_user||'—'],['Список RU',r.lists_from_server?'Сохранённый на сервере':(r.lists?.ru?.length||0)+' записей'],['Список RU-EU',r.lists_from_server?'Сохранённый на сервере':(r.lists?.eu?.length||0)+' записей']];
 $('summary').replaceChildren();for(const [title,value] of rows){const item=document.createElement('div');item.className='summary-item';const k=document.createElement('small');k.textContent=title;const v=document.createElement('strong');v.textContent=value;item.append(k,v);$('summary').append(item);}
}
async function poll(){clearTimeout(pollTimer);try{const j=await api('/api/jobs/'+jobId);reportSummary(j.report);$('modeBadge').textContent=j.demo?'ДЕМОНСТРАЦИЯ':'РЕАЛЬНЫЕ СЕРВЕРЫ';$('progressPanel').classList.remove('hidden');$('phase').textContent=j.phase;$('percentage').textContent=j.progress+'%';$('progressBar').style.width=j.progress+'%';$('log').replaceChildren();for(const e of j.events){const p=document.createElement('p');const t=document.createElement('time');t.textContent=e.time;const span=document.createElement('span');span.textContent=e.message;p.append(t,span);$('log').append(p);}$('log').scrollTop=$('log').scrollHeight;const active=j.status==='running';lockForm(active);$('cancel').classList.toggle('hidden',!active);$('download').classList.toggle('hidden',!j.download);$('download').textContent=j.demo?'Скачать пример':'Скачать профили';$('report').classList.toggle('hidden',active);$('again').classList.toggle('hidden',active);$('runBadge').textContent=active?'В ПРОЦЕССЕ':j.status==='success'?'ЗАВЕРШЕНО':j.status==='cancelled'?'ОСТАНОВЛЕНО':'ОШИБКА';if(!active){$('result').classList.remove('hidden');$('result').classList.toggle('error-result',j.status==='error');$('result').textContent=j.status==='success'?(j.demo?'Демонстрация завершена. Реальный VPN не устанавливался.':j.report.notice||'Операция завершена.'):(j.events[j.events.length-1]?.message||'Операция остановлена.');}else pollTimer=setTimeout(poll,700);}catch(e){lockForm(false);message(e.message);$('again').classList.remove('hidden');}}
$('cancel').onclick=async()=>{try{await api('/api/jobs/'+jobId+'/cancel',{});$('cancel').textContent='Ожидается завершение текущего этапа…';$('cancel').disabled=true;}catch(e){message(e.message);}};
async function download(suffix){try{const r=await fetch('/api/jobs/'+jobId+'/'+suffix,{headers:{'X-Local-Token':token}});if(!r.ok){const e=await r.json();throw Error(e.error);}const blob=await r.blob(),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=suffix==='report'?'vpn-report.json':($('modeBadge').textContent==='ДЕМОНСТРАЦИЯ'?'DEMO-preview.zip':'OpenVPN-profiles.zip');a.click();setTimeout(()=>URL.revokeObjectURL(url),10000);}catch(e){message(e.message);}}
$('download').onclick=()=>download('download');$('report').onclick=()=>download('report');
$('again').onclick=()=>{jobId='';sessionStorage.removeItem('vpn-job');clearTimeout(pollTimer);lockForm(false);$('progressPanel').classList.add('hidden');$('runControls').classList.remove('hidden');$('cancel').disabled=false;$('cancel').textContent='Остановить после текущего этапа';$('confirmation').value='';show(0);applyMode();};
api('/api/info').then(info=>{sshAvailable=info.ssh_available;platform=info.platform;for(const r of ['ru','nl'])$(r+'CommandOS').value=platform;applyMode();if(!jobId&&info.running.length)jobId=info.running[0];if(jobId){show(3);poll();}}).catch(e=>message(e.message));

function clearCommand(role){for(const suffix of ['CopyCommand','CopyButton','Fallback'])$(role+suffix).classList.add('hidden');$(role+'CopyButton').textContent='Скопировать команду';}
async function makeCommand(role){
 message('');const button=$(role+'MakeCommand');button.disabled=true;
 try{const result=await api('/api/ssh-command',{host:$(role+'Host').value,port:$(role+'Port').value,platform:$(role+'CommandOS').value,key_path:$(role+'KeyPath').value});$(role+'CopyCommand').textContent=result.command;$(role+'CopyCommand').classList.remove('hidden');$(role+'CopyButton').classList.remove('hidden');$(role+'CopyButton').textContent='Скопировать команду';$(role+'FallbackCommand').textContent=result.fallback;$(role+'Fallback').classList.toggle('hidden',!result.fallback);}
 catch(e){message(e.message);}finally{button.disabled=false;}
}
async function copyCommand(role,fallback){
 try{await navigator.clipboard.writeText($(role+(fallback?'FallbackCommand':'CopyCommand')).textContent);$(role+(fallback?'FallbackCopy':'CopyButton')).textContent='Скопировано ✓';}
 catch(e){message('Не удалось записать в буфер. Выделите команду и скопируйте вручную.');}
}

$('exitApp').onclick=async()=>{try{const answer=await api('/api/exit',{});clearTimeout(pollTimer);document.querySelectorAll('button,input,select,textarea').forEach(el=>el.disabled=true);message(answer.message);}catch(e){message(e.message);}};
