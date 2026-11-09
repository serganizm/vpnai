window.vpnaiConnectionNotice=(text,failed=false)=>{
 document.querySelector('.connection-result-overlay')?.remove();const overlay=document.createElement('div');overlay.className='connection-result-overlay';overlay.innerHTML='<div class="connection-result-message '+(failed?'is-error':'is-success')+'" role="alert"></div>';overlay.firstElementChild.textContent=text;document.body.append(overlay);
 const close=()=>{overlay.remove();document.removeEventListener('keydown',key);};const key=e=>{if(e.key==='Escape')close();};overlay.onclick=close;document.addEventListener('keydown',key);if(!failed)setTimeout(close,3000);
};
window.vpnaiLimits=(()=>{
 let current=null,error='',draft=null,draftRevision='',dirty=false,installation=2,installationDirty=false,reading=null,epoch=0;
 const title=n=>Number(n)===0?'Без ограничений':String(n);
 const escape=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const options=(value,inherit=false)=>{const values=[1,2,3,4,5,6,7,8,9,10,15,20,50,100,0];if(Number(value)>0&&!values.includes(Number(value)))values.push(Number(value));return (inherit?`<option value="-1" ${Number(value)===-1?'selected':''}>По умолчанию на сервере — ${current?title(current.default):'не считан'}</option>`:'')+values.map(n=>`<option value="${n}" ${Number(value)===n?'selected':''}>${title(n)}</option>`).join('');};
 async function call(operation,data={}){const response=await fetch('/api/admin/limits-'+operation,{method:'POST',headers:{'Content-Type':'application/json','X-Local-Token':sessionStorage.getItem('vpn-local-token')||''},body:JSON.stringify(data)});const result=await response.json();if(!response.ok)throw Error(result.error||'Не удалось прочитать лимиты.');return result;}
 function adopt(value){current=value;error='';if(!dirty){draft=value.default;draftRevision=value.revision;}if(!installationDirty)installation=value.default;draw();}
 function draw(){document.querySelectorAll('.connection-limit-panel').forEach(el=>{el.outerHTML=panel(el.dataset.limitContext);});}
 function syncFromServer(value,problem='',installationRead=false){if(installationRead)installationDirty=false;if(value)adopt(value);else{current=null;error=problem||'Лимиты не считаны.';draw();}}
 function reset(){epoch++;current=null;error='Лимиты не считаны.';draft=null;draftRevision='';dirty=false;installation=2;installationDirty=false;reading=null;draw();}
 async function read(){if(reading)return reading;const generation=epoch;reading=(async()=>{try{const value=await call('status');if(generation===epoch)adopt(value);}catch(e){if(generation===epoch)syncFromServer(null,e.message);}finally{if(generation===epoch)reading=null;}})();return reading;}
 const label=name=>{if(!current)return '—';const n=Object.hasOwn(current.users,name)?current.users[name]:current.default;return n===0?'∞':String(n);};
 function panel(context){const install=context==='installation';return `<section class="connection-limit-panel" data-limit-context="${context}"><div class="limit-panel-heading"><div class="limit-panel-topline"><span class="eyebrow">ПОДКЛЮЧЕНИЯ</span><span class="dns-preview-badge limit-panel-label">Максимальное кол-во подключений</span></div><h2>Одновременные подключения</h2><p>Лимит на одного пользователя по умолчанию.</p></div><div class="limit-settings-row"><label>Подключений с одного конфига<select data-limit-default="${context}" ${!install&&!current?'disabled':''}>${options(install?installation:draft??0)}</select></label><div class="limit-settings-copy"><strong>UDP и TCP считаются вместе</strong><p>Для каждого пользователя можно задать свой лимит в меню «Управлять».</p></div></div>${!install&&error?`<p role="alert" class="danger-text">${escape(error)}</p>`:''}<div class="limit-panel-footer"><span>${install?('Будет задан при установке или обновлении.'+(current&&!current.installed?' Первое включение перезапустит OpenVPN; устройства нужно переподключить.':'')):!current?'Сначала считайте лимиты с сервера.':current.installed?'Действует для пользователей без индивидуального лимита. Текущие подключения сохраняются.':'Первое включение требует перезапуска OpenVPN. Устройства потребуется переподключить.'}</span>${install?'':'<div class="admin-button-row"><button type="button" class="secondary" data-read-limits>Считать с сервера</button><button type="button" class="primary" data-save-limit-default '+(!current?'disabled':'')+'>Применить</button></div>'}</div></section>`;}
 function userPanel(name){const inherited=!current||!Object.hasOwn(current.users,name);return `<p>Пользователь <strong>${escape(name)}</strong></p><input type="hidden" data-limit-revision value="${escape(current?.revision||'')}"><label>Максимум подключений<select data-user-limit-value ${current?'':'disabled'}>${options(inherited?-1:current.users[name],true)}</select></label><div class="limit-dialog-info"><strong>Общий лимит для UDP и TCP</strong><p>Настройка применяется только к этому пользователю. При достижении лимита новые подключения не допускаются.</p><p>${current?.installed?'Уменьшение лимита сохраняет текущие подключения до отключения.':'Первое включение перезапустит OpenVPN. Устройства потребуется переподключить.'}</p>${error?`<p role="alert" class="danger-text">${escape(error)}</p>`:''}</div>`;}
 async function save(operation,data){if(!current)throw Error(error||'Сначала считайте настройки с сервера.');if(!confirm(current.installed?'Применить лимит подключений? Текущие сеансы сохранятся.':'Включить лимиты? OpenVPN будет перезапущен, все устройства потребуется переподключить.'))return false;adopt(await call(operation,{...data,confirmed:true,restart_confirmed:!current.installed}));dirty=false;draft=current.default;draftRevision=current.revision;draw();return true;}
 document.addEventListener('change',e=>{if(e.target.dataset.limitDefault==='installation'){installation=Number(e.target.value);installationDirty=true;window.dispatchEvent(new Event('vpnai-limits-draft'));}if(e.target.dataset.limitDefault==='management'){draft=Number(e.target.value);dirty=true;}});
 document.addEventListener('click',async e=>{if(e.target.closest('[data-read-limits]')){dirty=false;await read();}});
 const mount=document.getElementById('installationLimitsPreview');if(mount)mount.innerHTML=panel('installation');
 return{panel,label,userPanel,read,reset,syncFromServer,installation:()=>installation,restore:value=>{if(value!==undefined){installation=Number(value);installationDirty=true;draw();}},saveUser:(name,value,revision)=>save('user',{name,value:Number(value)===-1?null:Number(value),revision}),saveDefault:value=>save('default',{value:Number(value),revision:draftRevision})};
})();
window.vpnaiDNSPreview=(()=>{
 const openInitially=new URL(location.href).searchParams.get('preview')==='dns';
 const state={provider:'unchanged',primary:'',secondary:'',include:false,dirty:false,current:null,busy:false,installBusy:false,lastApplyError:'',reading:false,loadError:'',message:'Сначала считайте настройки сервера. Применение выполняется только по вашей команде.'};
 const presets={unchanged:['DNS клиента','Не передавать DNS'],google:['Google','8.8.8.8 · 8.8.4.4'],cloudflare:['Cloudflare','1.1.1.1 · 1.0.0.1'],custom:['Свои DNS','Публичные IPv4-адреса']};
 const escape=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 function chosen(){return{provider:state.provider,servers:state.provider==='google'?['8.8.8.8','8.8.4.4']:state.provider==='cloudflare'?['1.1.1.1','1.0.0.1']:state.provider==='custom'?[state.primary,...state.secondary?[state.secondary]:[]]:[]};}
 function valid(){if(state.provider!=='custom')return true;return chosen().servers.every(value=>/^\d{1,3}(\.\d{1,3}){3}$/.test(value)&&value.split('.').every(x=>+x<=255))&&!!state.primary;}
 function dirty(){state.dirty=true;state.include=false;state.message='Выбор изменён. На сервере настройки пока прежние.';window.dispatchEvent(new Event('vpnai-dns-draft'));}
 async function api(operation,data={}){const response=await fetch('/api/admin/'+operation,{method:'POST',headers:{'Content-Type':'application/json','X-Local-Token':sessionStorage.getItem('vpn-local-token')||''},body:JSON.stringify(data)});const answer=await response.json();if(!response.ok)throw Error(answer.error||'Не удалось выполнить DNS-операцию.');return answer;}
 function adopt(result,announce=true){state.current=result;state.provider=result.consistent?result.provider:'custom';state.primary=result.servers[0]||'';state.secondary=result.servers[1]||'';state.dirty=false;state.include=false;if(announce)window.dispatchEvent(new CustomEvent('vpnai-dns-draft',{detail:{read:true}}));}
 function panel(context,connected=window.vpnaiUnified?.connected||false){const custom=state.provider==='custom',addresses=chosen().servers;const current=state.current;const available=connected&&!state.busy&&!state.installBusy&&!state.reading;
 const actual=current?(current.consistent?(current.servers.length?current.servers.join(' · ')+(current.route==='eu'?'':' · путь через EU не подтверждён'):'DNS не передаётся'): 'Настройки UDP и TCP различаются'):state.loadError?'Не удалось считать DNS: '+state.loadError:'Настройки не считаны';
 return `<section class="dns-panel" data-dns-panel="${context}" aria-label="DNS для VPN-клиентов"><div class="dns-heading"><div><span class="eyebrow">DNS</span><h2>DNS для VPN-клиентов</h2><p>Общая настройка для устройств, подключённых к этому VPN.</p></div><span class="dns-preview-badge">Локально</span></div>${context==='management'?`<div class="dns-current"><span>Сейчас на сервере</span><strong>${escape(actual)}${current?.incomplete?' · остались маршруты незавершённого применения':''}</strong><button type="button" class="secondary" data-dns-read ${available?'':'disabled'}>Считать с сервера</button></div>`:`<div class="dns-current"><span>Сейчас на сервере</span><strong>${escape(actual)}${current?.incomplete?' · остались маршруты незавершённого применения':''}</strong></div>`}<div class="dns-options" role="group" aria-label="Провайдер DNS">${Object.entries(presets).map(([key,[title,detail]])=>`<button type="button" data-dns-provider="${key}" aria-pressed="${state.provider===key}" class="dns-option ${state.provider===key?'selected':''}" ${state.busy||state.installBusy?'disabled':''}><span class="dns-option-title">${title}<i aria-hidden="true"></i></span><small>${detail}</small></button>`).join('')}</div>${state.provider==='unchanged'?'<div class="dns-explanation">При применении DNS больше не будет передаваться клиентам. Будут использоваться настройки устройства и VPN-клиента.</div>':`<div class="dns-addresses"><label>Основной DNS<input data-dns-address="primary" inputmode="decimal" autocomplete="off" spellcheck="false" placeholder="Например: 9.9.9.9" value="${escape(addresses[0]||'')}" ${custom&&!state.busy&&!state.installBusy?'':'readonly'}></label><label>Дополнительный DNS <small>необязательно</small><input data-dns-address="secondary" inputmode="decimal" autocomplete="off" spellcheck="false" placeholder="Например: 149.112.112.112" value="${escape(addresses[1]||'')}" ${custom&&!state.busy&&!state.installBusy?'':'readonly'}></label></div><div class="dns-path"><span>Путь DNS-запросов</span><strong>Устройство → RU → EU → DNS</strong><p>Отдельные маршруты, без изменения ваших списков RU/EU.</p></div>`}<div class="dns-scope"><span>Все пользователи</span><span>UDP и TCP</span><span>После переподключения</span></div><p class="dns-client-note">Клиент должен принимать DNS от сервера. DNS самой ОС сервера не меняется. Собственные DoH-настройки приложений могут обходить этот выбор.</p><div class="dns-explanation">${context==='management'?'Перед применением создаётся копия настроек. OpenVPN перезапустится: текущие подключения прервутся, устройства потребуется переподключить.':'Настройка применяется только при запуске установки или обновления. Если не включать её в операцию, текущий DNS сохраняется.'}</div><div class="dns-actions">${context==='management'?`<button type="button" class="secondary" data-dns-probe ${available?'':'disabled'}>Проверить доступность</button><button type="button" class="primary" data-dns-apply ${available&&current?'':'disabled'}>Применить DNS</button>`:`<button type="button" class="secondary" data-dns-exclude ${state.busy||state.installBusy?'disabled':''}>Сохранить текущий DNS</button><button type="button" class="primary" data-dns-include ${state.busy||state.installBusy?'disabled':''}>Применить выбранный DNS</button>`}</div>${state.lastApplyError?`<div class="notice" role="alert">Последняя ошибка применения: ${escape(state.lastApplyError)}</div>`:''}<p class="dns-feedback" role="status">${escape(state.busy?'Выполняется DNS-операция…':state.reading?'Считываем текущий DNS с сервера…':context==='installation'&&state.include?'DNS включён в параметры операции: '+(chosen().servers.join(' · ')||'DNS клиента'):state.message)}</p></section>`;
 }
 function render(){document.querySelectorAll('[data-dns-panel]').forEach(el=>{el.outerHTML=panel(el.dataset.dnsPanel);});}
 document.addEventListener('click',async e=>{const b=e.target.closest('[data-dns-provider],[data-dns-read],[data-dns-probe],[data-dns-apply],[data-dns-include],[data-dns-exclude]');if(!b)return;e.stopImmediatePropagation();e.preventDefault();if(state.busy||state.installBusy||b.disabled)return;
 if(b.hasAttribute('data-dns-provider')){state.provider=b.dataset.dnsProvider;dirty();render();return;}
 if(b.hasAttribute('data-dns-exclude')){state.include=false;state.message='DNS не включён в операцию. Текущие настройки будут сохранены.';window.dispatchEvent(new Event('vpnai-dns-draft'));render();return;}
 if(!b.hasAttribute('data-dns-read')&&!valid()){state.message='Укажите один или два корректных публичных IPv4 DNS.';render();return;}
 if(b.hasAttribute('data-dns-include')){state.include=true;state.message='DNS включён в параметры операции.';window.dispatchEvent(new Event('vpnai-dns-draft'));render();return;}
 if(b.hasAttribute('data-dns-apply')&&!confirm('Применить DNS для всех VPN-клиентов? Будет создана резервная копия и перезапущен OpenVPN на российском сервере. Текущие подключения прервутся. Продолжить?'))return;
 state.busy=true;render();try{
 if(b.hasAttribute('data-dns-read')){adopt(await api('dns-status'));state.message=state.current.consistent?'Настройки прочитаны. Сервер не изменён.':'DNS UDP/TCP различаются. Выберите общую настройку для обоих профилей.';}
 else if(b.hasAttribute('data-dns-probe')){const result=await api('dns-probe',chosen());state.message=result.checks.length?result.checks.map(x=>x.server+': UDP '+(x.udp?'доступен':'нет ответа')+', TCP '+(x.tcp?'доступен':'нет ответа')).join('; '):'DNS не выбран: проверять адреса не требуется.';}
 else {const result=await api('dns-apply',{...chosen(),revision:state.current.revision,confirmed:true});adopt(result);state.lastApplyError='';state.message='DNS применён. Переподключите устройства. Резервная копия: '+result.backup;}
 }catch(error){state.message=error.message;if(b.hasAttribute('data-dns-apply')){state.lastApplyError=error.message;state.current=null;state.message+=' Считайте настройки заново перед повторным применением.';}}finally{state.busy=false;render();}
 },true);
 window.addEventListener('vpnai-installer-busy',e=>{state.installBusy=!!e.detail;render();});
 document.addEventListener('input',e=>{if(e.target.dataset.dnsAddress){state[e.target.dataset.dnsAddress]=e.target.value.trim();dirty();document.querySelectorAll('[data-dns-address="'+e.target.dataset.dnsAddress+'"]').forEach(input=>{if(input!==e.target)input.value=e.target.value;});}});
 const slot=document.getElementById('installationDNSPreview');if(slot)slot.innerHTML=panel('installation');
 function syncFromServer(result,automatic,error=''){
  state.loadError=error||'';
  if(!result){state.current=null;state.message='DNS не считан. Текущие DNS не будут изменены автоматически.';render();return;}
  state.current=result;
  if(!automatic||(!state.dirty&&!state.include)){
   adopt(result,false);state.message=result.consistent?'Текущий DNS получен вместе с настройками сервера. Без включения в операцию он сохранится.':'DNS UDP и TCP различаются. Выберите общий DNS, только если хотите их изменить.';
  }
  render();
 }
 return {panel,openInitially,syncFromServer,setReading:value=>{state.reading=!!value;render();},exclude:()=>{state.include=false;render();},installation:()=>state.include?chosen():undefined,description:()=>state.include?(chosen().servers.join(' · ')||'DNS клиента'):'Сохранить текущие настройки',restore:d=>{if(d){state.provider=d.provider;state.primary=d.servers?.[0]||'';state.secondary=d.servers?.[1]||'';state.include=true;render();}}};
})();
window.vpnaiServerFiles={adapters:[]};
window.vpnaiUnified={installerReady:false,installDraft:null,eu_ssh:'direct',eu_target:'public'};
function syncWorkspaceConnectionBadge(){
 const badge=document.getElementById('workspaceConnectionBadge');if(!badge)return;
 const connected=['modeInstall','modeAdmin'].some(id=>document.getElementById(id)?.classList.contains('server-connected'));
 window.vpnaiUnified.connected=connected;
 badge.classList.toggle('is-connected',connected);badge.classList.toggle('is-disconnected',!connected);
 const text=connected?'Подключено':'Нет подключения',label=badge.querySelector('.connection-badge-text');if(label.textContent!==text)label.textContent=text;
 badge.title='Общее подключение к RU и EU: '+text;
 const caption=document.getElementById('workspaceModeLabel');if(caption)caption.textContent=({connection:'Подключение',install:'Установка',admin:'Управление'})[document.body.dataset.workspaceMode]||'Подключение';
}
//---------------------------------------------------------------------
//
// QR Code Generator for JavaScript
//
// Copyright (c) 2009 Kazuhiko Arase
//
// URL: http://www.d-project.com/
//
// Licensed under the MIT license:
//  http://www.opensource.org/licenses/mit-license.php
//
// The word 'QR Code' is registered trademark of
// DENSO WAVE INCORPORATED
//  http://www.denso-wave.com/qrcode/faqpatent-e.html
//
//---------------------------------------------------------------------

var qrcode = function() {

  //---------------------------------------------------------------------
  // qrcode
  //---------------------------------------------------------------------

  /**
   * qrcode
   * @param typeNumber 1 to 40
   * @param errorCorrectionLevel 'L','M','Q','H'
   */
  var qrcode = function(typeNumber, errorCorrectionLevel) {

    var PAD0 = 0xEC;
    var PAD1 = 0x11;

    var _typeNumber = typeNumber;
    var _errorCorrectionLevel = QRErrorCorrectionLevel[errorCorrectionLevel];
    var _modules = null;
    var _moduleCount = 0;
    var _dataCache = null;
    var _dataList = [];

    var _this = {};

    var makeImpl = function(test, maskPattern) {

      _moduleCount = _typeNumber * 4 + 17;
      _modules = function(moduleCount) {
        var modules = new Array(moduleCount);
        for (var row = 0; row < moduleCount; row += 1) {
          modules[row] = new Array(moduleCount);
          for (var col = 0; col < moduleCount; col += 1) {
            modules[row][col] = null;
          }
        }
        return modules;
      }(_moduleCount);

      setupPositionProbePattern(0, 0);
      setupPositionProbePattern(_moduleCount - 7, 0);
      setupPositionProbePattern(0, _moduleCount - 7);
      setupPositionAdjustPattern();
      setupTimingPattern();
      setupTypeInfo(test, maskPattern);

      if (_typeNumber >= 7) {
        setupTypeNumber(test);
      }

      if (_dataCache == null) {
        _dataCache = createData(_typeNumber, _errorCorrectionLevel, _dataList);
      }

      mapData(_dataCache, maskPattern);
    };

    var setupPositionProbePattern = function(row, col) {

      for (var r = -1; r <= 7; r += 1) {

        if (row + r <= -1 || _moduleCount <= row + r) continue;

        for (var c = -1; c <= 7; c += 1) {

          if (col + c <= -1 || _moduleCount <= col + c) continue;

          if ( (0 <= r && r <= 6 && (c == 0 || c == 6) )
              || (0 <= c && c <= 6 && (r == 0 || r == 6) )
              || (2 <= r && r <= 4 && 2 <= c && c <= 4) ) {
            _modules[row + r][col + c] = true;
          } else {
            _modules[row + r][col + c] = false;
          }
        }
      }
    };

    var getBestMaskPattern = function() {

      var minLostPoint = 0;
      var pattern = 0;

      for (var i = 0; i < 8; i += 1) {

        makeImpl(true, i);

        var lostPoint = QRUtil.getLostPoint(_this);

        if (i == 0 || minLostPoint > lostPoint) {
          minLostPoint = lostPoint;
          pattern = i;
        }
      }

      return pattern;
    };

    var setupTimingPattern = function() {

      for (var r = 8; r < _moduleCount - 8; r += 1) {
        if (_modules[r][6] != null) {
          continue;
        }
        _modules[r][6] = (r % 2 == 0);
      }

      for (var c = 8; c < _moduleCount - 8; c += 1) {
        if (_modules[6][c] != null) {
          continue;
        }
        _modules[6][c] = (c % 2 == 0);
      }
    };

    var setupPositionAdjustPattern = function() {

      var pos = QRUtil.getPatternPosition(_typeNumber);

      for (var i = 0; i < pos.length; i += 1) {

        for (var j = 0; j < pos.length; j += 1) {

          var row = pos[i];
          var col = pos[j];

          if (_modules[row][col] != null) {
            continue;
          }

          for (var r = -2; r <= 2; r += 1) {

            for (var c = -2; c <= 2; c += 1) {

              if (r == -2 || r == 2 || c == -2 || c == 2
                  || (r == 0 && c == 0) ) {
                _modules[row + r][col + c] = true;
              } else {
                _modules[row + r][col + c] = false;
              }
            }
          }
        }
      }
    };

    var setupTypeNumber = function(test) {

      var bits = QRUtil.getBCHTypeNumber(_typeNumber);

      for (var i = 0; i < 18; i += 1) {
        var mod = (!test && ( (bits >> i) & 1) == 1);
        _modules[Math.floor(i / 3)][i % 3 + _moduleCount - 8 - 3] = mod;
      }

      for (var i = 0; i < 18; i += 1) {
        var mod = (!test && ( (bits >> i) & 1) == 1);
        _modules[i % 3 + _moduleCount - 8 - 3][Math.floor(i / 3)] = mod;
      }
    };

    var setupTypeInfo = function(test, maskPattern) {

      var data = (_errorCorrectionLevel << 3) | maskPattern;
      var bits = QRUtil.getBCHTypeInfo(data);

      // vertical
      for (var i = 0; i < 15; i += 1) {

        var mod = (!test && ( (bits >> i) & 1) == 1);

        if (i < 6) {
          _modules[i][8] = mod;
        } else if (i < 8) {
          _modules[i + 1][8] = mod;
        } else {
          _modules[_moduleCount - 15 + i][8] = mod;
        }
      }

      // horizontal
      for (var i = 0; i < 15; i += 1) {

        var mod = (!test && ( (bits >> i) & 1) == 1);

        if (i < 8) {
          _modules[8][_moduleCount - i - 1] = mod;
        } else if (i < 9) {
          _modules[8][15 - i - 1 + 1] = mod;
        } else {
          _modules[8][15 - i - 1] = mod;
        }
      }

      // fixed module
      _modules[_moduleCount - 8][8] = (!test);
    };

    var mapData = function(data, maskPattern) {

      var inc = -1;
      var row = _moduleCount - 1;
      var bitIndex = 7;
      var byteIndex = 0;
      var maskFunc = QRUtil.getMaskFunction(maskPattern);

      for (var col = _moduleCount - 1; col > 0; col -= 2) {

        if (col == 6) col -= 1;

        while (true) {

          for (var c = 0; c < 2; c += 1) {

            if (_modules[row][col - c] == null) {

              var dark = false;

              if (byteIndex < data.length) {
                dark = ( ( (data[byteIndex] >>> bitIndex) & 1) == 1);
              }

              var mask = maskFunc(row, col - c);

              if (mask) {
                dark = !dark;
              }

              _modules[row][col - c] = dark;
              bitIndex -= 1;

              if (bitIndex == -1) {
                byteIndex += 1;
                bitIndex = 7;
              }
            }
          }

          row += inc;

          if (row < 0 || _moduleCount <= row) {
            row -= inc;
            inc = -inc;
            break;
          }
        }
      }
    };

    var createBytes = function(buffer, rsBlocks) {

      var offset = 0;

      var maxDcCount = 0;
      var maxEcCount = 0;

      var dcdata = new Array(rsBlocks.length);
      var ecdata = new Array(rsBlocks.length);

      for (var r = 0; r < rsBlocks.length; r += 1) {

        var dcCount = rsBlocks[r].dataCount;
        var ecCount = rsBlocks[r].totalCount - dcCount;

        maxDcCount = Math.max(maxDcCount, dcCount);
        maxEcCount = Math.max(maxEcCount, ecCount);

        dcdata[r] = new Array(dcCount);

        for (var i = 0; i < dcdata[r].length; i += 1) {
          dcdata[r][i] = 0xff & buffer.getBuffer()[i + offset];
        }
        offset += dcCount;

        var rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);
        var rawPoly = qrPolynomial(dcdata[r], rsPoly.getLength() - 1);

        var modPoly = rawPoly.mod(rsPoly);
        ecdata[r] = new Array(rsPoly.getLength() - 1);
        for (var i = 0; i < ecdata[r].length; i += 1) {
          var modIndex = i + modPoly.getLength() - ecdata[r].length;
          ecdata[r][i] = (modIndex >= 0)? modPoly.getAt(modIndex) : 0;
        }
      }

      var totalCodeCount = 0;
      for (var i = 0; i < rsBlocks.length; i += 1) {
        totalCodeCount += rsBlocks[i].totalCount;
      }

      var data = new Array(totalCodeCount);
      var index = 0;

      for (var i = 0; i < maxDcCount; i += 1) {
        for (var r = 0; r < rsBlocks.length; r += 1) {
          if (i < dcdata[r].length) {
            data[index] = dcdata[r][i];
            index += 1;
          }
        }
      }

      for (var i = 0; i < maxEcCount; i += 1) {
        for (var r = 0; r < rsBlocks.length; r += 1) {
          if (i < ecdata[r].length) {
            data[index] = ecdata[r][i];
            index += 1;
          }
        }
      }

      return data;
    };

    var createData = function(typeNumber, errorCorrectionLevel, dataList) {

      var rsBlocks = QRRSBlock.getRSBlocks(typeNumber, errorCorrectionLevel);

      var buffer = qrBitBuffer();

      for (var i = 0; i < dataList.length; i += 1) {
        var data = dataList[i];
        buffer.put(data.getMode(), 4);
        buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber) );
        data.write(buffer);
      }

      // calc num max data.
      var totalDataCount = 0;
      for (var i = 0; i < rsBlocks.length; i += 1) {
        totalDataCount += rsBlocks[i].dataCount;
      }

      if (buffer.getLengthInBits() > totalDataCount * 8) {
        throw 'code length overflow. ('
          + buffer.getLengthInBits()
          + '>'
          + totalDataCount * 8
          + ')';
      }

      // end code
      if (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {
        buffer.put(0, 4);
      }

      // padding
      while (buffer.getLengthInBits() % 8 != 0) {
        buffer.putBit(false);
      }

      // padding
      while (true) {

        if (buffer.getLengthInBits() >= totalDataCount * 8) {
          break;
        }
        buffer.put(PAD0, 8);

        if (buffer.getLengthInBits() >= totalDataCount * 8) {
          break;
        }
        buffer.put(PAD1, 8);
      }

      return createBytes(buffer, rsBlocks);
    };

    _this.addData = function(data, mode) {

      mode = mode || 'Byte';

      var newData = null;

      switch(mode) {
      case 'Numeric' :
        newData = qrNumber(data);
        break;
      case 'Alphanumeric' :
        newData = qrAlphaNum(data);
        break;
      case 'Byte' :
        newData = qr8BitByte(data);
        break;
      case 'Kanji' :
        newData = qrKanji(data);
        break;
      default :
        throw 'mode:' + mode;
      }

      _dataList.push(newData);
      _dataCache = null;
    };

    _this.isDark = function(row, col) {
      if (row < 0 || _moduleCount <= row || col < 0 || _moduleCount <= col) {
        throw row + ',' + col;
      }
      return _modules[row][col];
    };

    _this.getModuleCount = function() {
      return _moduleCount;
    };

    _this.make = function() {
      if (_typeNumber < 1) {
        var typeNumber = 1;

        for (; typeNumber < 40; typeNumber++) {
          var rsBlocks = QRRSBlock.getRSBlocks(typeNumber, _errorCorrectionLevel);
          var buffer = qrBitBuffer();

          for (var i = 0; i < _dataList.length; i++) {
            var data = _dataList[i];
            buffer.put(data.getMode(), 4);
            buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber) );
            data.write(buffer);
          }

          var totalDataCount = 0;
          for (var i = 0; i < rsBlocks.length; i++) {
            totalDataCount += rsBlocks[i].dataCount;
          }

          if (buffer.getLengthInBits() <= totalDataCount * 8) {
            break;
          }
        }

        _typeNumber = typeNumber;
      }

      makeImpl(false, getBestMaskPattern() );
    };

    _this.createTableTag = function(cellSize, margin) {

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      var qrHtml = '';

      qrHtml += '<table style="';
      qrHtml += ' border-width: 0px; border-style: none;';
      qrHtml += ' border-collapse: collapse;';
      qrHtml += ' padding: 0px; margin: ' + margin + 'px;';
      qrHtml += '">';
      qrHtml += '<tbody>';

      for (var r = 0; r < _this.getModuleCount(); r += 1) {

        qrHtml += '<tr>';

        for (var c = 0; c < _this.getModuleCount(); c += 1) {
          qrHtml += '<td style="';
          qrHtml += ' border-width: 0px; border-style: none;';
          qrHtml += ' border-collapse: collapse;';
          qrHtml += ' padding: 0px; margin: 0px;';
          qrHtml += ' width: ' + cellSize + 'px;';
          qrHtml += ' height: ' + cellSize + 'px;';
          qrHtml += ' background-color: ';
          qrHtml += _this.isDark(r, c)? '#000000' : '#ffffff';
          qrHtml += ';';
          qrHtml += '"/>';
        }

        qrHtml += '</tr>';
      }

      qrHtml += '</tbody>';
      qrHtml += '</table>';

      return qrHtml;
    };

    _this.createSvgTag = function(cellSize, margin, alt, title) {

      var opts = {};
      if (typeof arguments[0] == 'object') {
        // Called by options.
        opts = arguments[0];
        // overwrite cellSize and margin.
        cellSize = opts.cellSize;
        margin = opts.margin;
        alt = opts.alt;
        title = opts.title;
      }

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      // Compose alt property surrogate
      alt = (typeof alt === 'string') ? {text: alt} : alt || {};
      alt.text = alt.text || null;
      alt.id = (alt.text) ? alt.id || 'qrcode-description' : null;

      // Compose title property surrogate
      title = (typeof title === 'string') ? {text: title} : title || {};
      title.text = title.text || null;
      title.id = (title.text) ? title.id || 'qrcode-title' : null;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var c, mc, r, mr, qrSvg='', rect;

      rect = 'l' + cellSize + ',0 0,' + cellSize +
        ' -' + cellSize + ',0 0,-' + cellSize + 'z ';

      qrSvg += '<svg version="1.1" xmlns="http://www.w3.org/2000/svg"';
      qrSvg += !opts.scalable ? ' width="' + size + 'px" height="' + size + 'px"' : '';
      qrSvg += ' viewBox="0 0 ' + size + ' ' + size + '" ';
      qrSvg += ' preserveAspectRatio="xMinYMin meet"';
      qrSvg += (title.text || alt.text) ? ' role="img" aria-labelledby="' +
          escapeXml([title.id, alt.id].join(' ').trim() ) + '"' : '';
      qrSvg += '>';
      qrSvg += (title.text) ? '<title id="' + escapeXml(title.id) + '">' +
          escapeXml(title.text) + '</title>' : '';
      qrSvg += (alt.text) ? '<description id="' + escapeXml(alt.id) + '">' +
          escapeXml(alt.text) + '</description>' : '';
      qrSvg += '<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>';
      qrSvg += '<path d="';

      for (r = 0; r < _this.getModuleCount(); r += 1) {
        mr = r * cellSize + margin;
        for (c = 0; c < _this.getModuleCount(); c += 1) {
          if (_this.isDark(r, c) ) {
            mc = c*cellSize+margin;
            qrSvg += 'M' + mc + ',' + mr + rect;
          }
        }
      }

      qrSvg += '" stroke="transparent" fill="black"/>';
      qrSvg += '</svg>';

      return qrSvg;
    };

    _this.createDataURL = function(cellSize, margin) {

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var min = margin;
      var max = size - margin;

      return createDataURL(size, size, function(x, y) {
        if (min <= x && x < max && min <= y && y < max) {
          var c = Math.floor( (x - min) / cellSize);
          var r = Math.floor( (y - min) / cellSize);
          return _this.isDark(r, c)? 0 : 1;
        } else {
          return 1;
        }
      } );
    };

    _this.createImgTag = function(cellSize, margin, alt) {

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;

      var img = '';
      img += '<img';
      img += '\u0020src="';
      img += _this.createDataURL(cellSize, margin);
      img += '"';
      img += '\u0020width="';
      img += size;
      img += '"';
      img += '\u0020height="';
      img += size;
      img += '"';
      if (alt) {
        img += '\u0020alt="';
        img += escapeXml(alt);
        img += '"';
      }
      img += '/>';

      return img;
    };

    var escapeXml = function(s) {
      var escaped = '';
      for (var i = 0; i < s.length; i += 1) {
        var c = s.charAt(i);
        switch(c) {
        case '<': escaped += '&lt;'; break;
        case '>': escaped += '&gt;'; break;
        case '&': escaped += '&amp;'; break;
        case '"': escaped += '&quot;'; break;
        default : escaped += c; break;
        }
      }
      return escaped;
    };

    var _createHalfASCII = function(margin) {
      var cellSize = 1;
      margin = (typeof margin == 'undefined')? cellSize * 2 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var min = margin;
      var max = size - margin;

      var y, x, r1, r2, p;

      var blocks = {
        '██': '█',
        '█ ': '▀',
        ' █': '▄',
        '  ': ' '
      };

      var blocksLastLineNoMargin = {
        '██': '▀',
        '█ ': '▀',
        ' █': ' ',
        '  ': ' '
      };

      var ascii = '';
      for (y = 0; y < size; y += 2) {
        r1 = Math.floor((y - min) / cellSize);
        r2 = Math.floor((y + 1 - min) / cellSize);
        for (x = 0; x < size; x += 1) {
          p = '█';

          if (min <= x && x < max && min <= y && y < max && _this.isDark(r1, Math.floor((x - min) / cellSize))) {
            p = ' ';
          }

          if (min <= x && x < max && min <= y+1 && y+1 < max && _this.isDark(r2, Math.floor((x - min) / cellSize))) {
            p += ' ';
          }
          else {
            p += '█';
          }

          // Output 2 characters per pixel, to create full square. 1 character per pixels gives only half width of square.
          ascii += (margin < 1 && y+1 >= max) ? blocksLastLineNoMargin[p] : blocks[p];
        }

        ascii += '\n';
      }

      if (size % 2 && margin > 0) {
        return ascii.substring(0, ascii.length - size - 1) + Array(size+1).join('▀');
      }

      return ascii.substring(0, ascii.length-1);
    };

    _this.createASCII = function(cellSize, margin) {
      cellSize = cellSize || 1;

      if (cellSize < 2) {
        return _createHalfASCII(margin);
      }

      cellSize -= 1;
      margin = (typeof margin == 'undefined')? cellSize * 2 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var min = margin;
      var max = size - margin;

      var y, x, r, p;

      var white = Array(cellSize+1).join('██');
      var black = Array(cellSize+1).join('  ');

      var ascii = '';
      var line = '';
      for (y = 0; y < size; y += 1) {
        r = Math.floor( (y - min) / cellSize);
        line = '';
        for (x = 0; x < size; x += 1) {
          p = 1;

          if (min <= x && x < max && min <= y && y < max && _this.isDark(r, Math.floor((x - min) / cellSize))) {
            p = 0;
          }

          // Output 2 characters per pixel, to create full square. 1 character per pixels gives only half width of square.
          line += p ? white : black;
        }

        for (r = 0; r < cellSize; r += 1) {
          ascii += line + '\n';
        }
      }

      return ascii.substring(0, ascii.length-1);
    };

    _this.renderTo2dContext = function(context, cellSize) {
      cellSize = cellSize || 2;
      var length = _this.getModuleCount();
      for (var row = 0; row < length; row++) {
        for (var col = 0; col < length; col++) {
          context.fillStyle = _this.isDark(row, col) ? 'black' : 'white';
          context.fillRect(row * cellSize, col * cellSize, cellSize, cellSize);
        }
      }
    }

    return _this;
  };

  //---------------------------------------------------------------------
  // qrcode.stringToBytes
  //---------------------------------------------------------------------

  qrcode.stringToBytesFuncs = {
    'default' : function(s) {
      var bytes = [];
      for (var i = 0; i < s.length; i += 1) {
        var c = s.charCodeAt(i);
        bytes.push(c & 0xff);
      }
      return bytes;
    }
  };

  qrcode.stringToBytes = qrcode.stringToBytesFuncs['default'];

  //---------------------------------------------------------------------
  // qrcode.createStringToBytes
  //---------------------------------------------------------------------

  /**
   * @param unicodeData base64 string of byte array.
   * [16bit Unicode],[16bit Bytes], ...
   * @param numChars
   */
  qrcode.createStringToBytes = function(unicodeData, numChars) {

    // create conversion map.

    var unicodeMap = function() {

      var bin = base64DecodeInputStream(unicodeData);
      var read = function() {
        var b = bin.read();
        if (b == -1) throw 'eof';
        return b;
      };

      var count = 0;
      var unicodeMap = {};
      while (true) {
        var b0 = bin.read();
        if (b0 == -1) break;
        var b1 = read();
        var b2 = read();
        var b3 = read();
        var k = String.fromCharCode( (b0 << 8) | b1);
        var v = (b2 << 8) | b3;
        unicodeMap[k] = v;
        count += 1;
      }
      if (count != numChars) {
        throw count + ' != ' + numChars;
      }

      return unicodeMap;
    }();

    var unknownChar = '?'.charCodeAt(0);

    return function(s) {
      var bytes = [];
      for (var i = 0; i < s.length; i += 1) {
        var c = s.charCodeAt(i);
        if (c < 128) {
          bytes.push(c);
        } else {
          var b = unicodeMap[s.charAt(i)];
          if (typeof b == 'number') {
            if ( (b & 0xff) == b) {
              // 1byte
              bytes.push(b);
            } else {
              // 2bytes
              bytes.push(b >>> 8);
              bytes.push(b & 0xff);
            }
          } else {
            bytes.push(unknownChar);
          }
        }
      }
      return bytes;
    };
  };

  //---------------------------------------------------------------------
  // QRMode
  //---------------------------------------------------------------------

  var QRMode = {
    MODE_NUMBER :    1 << 0,
    MODE_ALPHA_NUM : 1 << 1,
    MODE_8BIT_BYTE : 1 << 2,
    MODE_KANJI :     1 << 3
  };

  //---------------------------------------------------------------------
  // QRErrorCorrectionLevel
  //---------------------------------------------------------------------

  var QRErrorCorrectionLevel = {
    L : 1,
    M : 0,
    Q : 3,
    H : 2
  };

  //---------------------------------------------------------------------
  // QRMaskPattern
  //---------------------------------------------------------------------

  var QRMaskPattern = {
    PATTERN000 : 0,
    PATTERN001 : 1,
    PATTERN010 : 2,
    PATTERN011 : 3,
    PATTERN100 : 4,
    PATTERN101 : 5,
    PATTERN110 : 6,
    PATTERN111 : 7
  };

  //---------------------------------------------------------------------
  // QRUtil
  //---------------------------------------------------------------------

  var QRUtil = function() {

    var PATTERN_POSITION_TABLE = [
      [],
      [6, 18],
      [6, 22],
      [6, 26],
      [6, 30],
      [6, 34],
      [6, 22, 38],
      [6, 24, 42],
      [6, 26, 46],
      [6, 28, 50],
      [6, 30, 54],
      [6, 32, 58],
      [6, 34, 62],
      [6, 26, 46, 66],
      [6, 26, 48, 70],
      [6, 26, 50, 74],
      [6, 30, 54, 78],
      [6, 30, 56, 82],
      [6, 30, 58, 86],
      [6, 34, 62, 90],
      [6, 28, 50, 72, 94],
      [6, 26, 50, 74, 98],
      [6, 30, 54, 78, 102],
      [6, 28, 54, 80, 106],
      [6, 32, 58, 84, 110],
      [6, 30, 58, 86, 114],
      [6, 34, 62, 90, 118],
      [6, 26, 50, 74, 98, 122],
      [6, 30, 54, 78, 102, 126],
      [6, 26, 52, 78, 104, 130],
      [6, 30, 56, 82, 108, 134],
      [6, 34, 60, 86, 112, 138],
      [6, 30, 58, 86, 114, 142],
      [6, 34, 62, 90, 118, 146],
      [6, 30, 54, 78, 102, 126, 150],
      [6, 24, 50, 76, 102, 128, 154],
      [6, 28, 54, 80, 106, 132, 158],
      [6, 32, 58, 84, 110, 136, 162],
      [6, 26, 54, 82, 110, 138, 166],
      [6, 30, 58, 86, 114, 142, 170]
    ];
    var G15 = (1 << 10) | (1 << 8) | (1 << 5) | (1 << 4) | (1 << 2) | (1 << 1) | (1 << 0);
    var G18 = (1 << 12) | (1 << 11) | (1 << 10) | (1 << 9) | (1 << 8) | (1 << 5) | (1 << 2) | (1 << 0);
    var G15_MASK = (1 << 14) | (1 << 12) | (1 << 10) | (1 << 4) | (1 << 1);

    var _this = {};

    var getBCHDigit = function(data) {
      var digit = 0;
      while (data != 0) {
        digit += 1;
        data >>>= 1;
      }
      return digit;
    };

    _this.getBCHTypeInfo = function(data) {
      var d = data << 10;
      while (getBCHDigit(d) - getBCHDigit(G15) >= 0) {
        d ^= (G15 << (getBCHDigit(d) - getBCHDigit(G15) ) );
      }
      return ( (data << 10) | d) ^ G15_MASK;
    };

    _this.getBCHTypeNumber = function(data) {
      var d = data << 12;
      while (getBCHDigit(d) - getBCHDigit(G18) >= 0) {
        d ^= (G18 << (getBCHDigit(d) - getBCHDigit(G18) ) );
      }
      return (data << 12) | d;
    };

    _this.getPatternPosition = function(typeNumber) {
      return PATTERN_POSITION_TABLE[typeNumber - 1];
    };

    _this.getMaskFunction = function(maskPattern) {

      switch (maskPattern) {

      case QRMaskPattern.PATTERN000 :
        return function(i, j) { return (i + j) % 2 == 0; };
      case QRMaskPattern.PATTERN001 :
        return function(i, j) { return i % 2 == 0; };
      case QRMaskPattern.PATTERN010 :
        return function(i, j) { return j % 3 == 0; };
      case QRMaskPattern.PATTERN011 :
        return function(i, j) { return (i + j) % 3 == 0; };
      case QRMaskPattern.PATTERN100 :
        return function(i, j) { return (Math.floor(i / 2) + Math.floor(j / 3) ) % 2 == 0; };
      case QRMaskPattern.PATTERN101 :
        return function(i, j) { return (i * j) % 2 + (i * j) % 3 == 0; };
      case QRMaskPattern.PATTERN110 :
        return function(i, j) { return ( (i * j) % 2 + (i * j) % 3) % 2 == 0; };
      case QRMaskPattern.PATTERN111 :
        return function(i, j) { return ( (i * j) % 3 + (i + j) % 2) % 2 == 0; };

      default :
        throw 'bad maskPattern:' + maskPattern;
      }
    };

    _this.getErrorCorrectPolynomial = function(errorCorrectLength) {
      var a = qrPolynomial([1], 0);
      for (var i = 0; i < errorCorrectLength; i += 1) {
        a = a.multiply(qrPolynomial([1, QRMath.gexp(i)], 0) );
      }
      return a;
    };

    _this.getLengthInBits = function(mode, type) {

      if (1 <= type && type < 10) {

        // 1 - 9

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 10;
        case QRMode.MODE_ALPHA_NUM : return 9;
        case QRMode.MODE_8BIT_BYTE : return 8;
        case QRMode.MODE_KANJI     : return 8;
        default :
          throw 'mode:' + mode;
        }

      } else if (type < 27) {

        // 10 - 26

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 12;
        case QRMode.MODE_ALPHA_NUM : return 11;
        case QRMode.MODE_8BIT_BYTE : return 16;
        case QRMode.MODE_KANJI     : return 10;
        default :
          throw 'mode:' + mode;
        }

      } else if (type < 41) {

        // 27 - 40

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 14;
        case QRMode.MODE_ALPHA_NUM : return 13;
        case QRMode.MODE_8BIT_BYTE : return 16;
        case QRMode.MODE_KANJI     : return 12;
        default :
          throw 'mode:' + mode;
        }

      } else {
        throw 'type:' + type;
      }
    };

    _this.getLostPoint = function(qrcode) {

      var moduleCount = qrcode.getModuleCount();

      var lostPoint = 0;

      // LEVEL1

      for (var row = 0; row < moduleCount; row += 1) {
        for (var col = 0; col < moduleCount; col += 1) {

          var sameCount = 0;
          var dark = qrcode.isDark(row, col);

          for (var r = -1; r <= 1; r += 1) {

            if (row + r < 0 || moduleCount <= row + r) {
              continue;
            }

            for (var c = -1; c <= 1; c += 1) {

              if (col + c < 0 || moduleCount <= col + c) {
                continue;
              }

              if (r == 0 && c == 0) {
                continue;
              }

              if (dark == qrcode.isDark(row + r, col + c) ) {
                sameCount += 1;
              }
            }
          }

          if (sameCount > 5) {
            lostPoint += (3 + sameCount - 5);
          }
        }
      };

      // LEVEL2

      for (var row = 0; row < moduleCount - 1; row += 1) {
        for (var col = 0; col < moduleCount - 1; col += 1) {
          var count = 0;
          if (qrcode.isDark(row, col) ) count += 1;
          if (qrcode.isDark(row + 1, col) ) count += 1;
          if (qrcode.isDark(row, col + 1) ) count += 1;
          if (qrcode.isDark(row + 1, col + 1) ) count += 1;
          if (count == 0 || count == 4) {
            lostPoint += 3;
          }
        }
      }

      // LEVEL3

      for (var row = 0; row < moduleCount; row += 1) {
        for (var col = 0; col < moduleCount - 6; col += 1) {
          if (qrcode.isDark(row, col)
              && !qrcode.isDark(row, col + 1)
              &&  qrcode.isDark(row, col + 2)
              &&  qrcode.isDark(row, col + 3)
              &&  qrcode.isDark(row, col + 4)
              && !qrcode.isDark(row, col + 5)
              &&  qrcode.isDark(row, col + 6) ) {
            lostPoint += 40;
          }
        }
      }

      for (var col = 0; col < moduleCount; col += 1) {
        for (var row = 0; row < moduleCount - 6; row += 1) {
          if (qrcode.isDark(row, col)
              && !qrcode.isDark(row + 1, col)
              &&  qrcode.isDark(row + 2, col)
              &&  qrcode.isDark(row + 3, col)
              &&  qrcode.isDark(row + 4, col)
              && !qrcode.isDark(row + 5, col)
              &&  qrcode.isDark(row + 6, col) ) {
            lostPoint += 40;
          }
        }
      }

      // LEVEL4

      var darkCount = 0;

      for (var col = 0; col < moduleCount; col += 1) {
        for (var row = 0; row < moduleCount; row += 1) {
          if (qrcode.isDark(row, col) ) {
            darkCount += 1;
          }
        }
      }

      var ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;
      lostPoint += ratio * 10;

      return lostPoint;
    };

    return _this;
  }();

  //---------------------------------------------------------------------
  // QRMath
  //---------------------------------------------------------------------

  var QRMath = function() {

    var EXP_TABLE = new Array(256);
    var LOG_TABLE = new Array(256);

    // initialize tables
    for (var i = 0; i < 8; i += 1) {
      EXP_TABLE[i] = 1 << i;
    }
    for (var i = 8; i < 256; i += 1) {
      EXP_TABLE[i] = EXP_TABLE[i - 4]
        ^ EXP_TABLE[i - 5]
        ^ EXP_TABLE[i - 6]
        ^ EXP_TABLE[i - 8];
    }
    for (var i = 0; i < 255; i += 1) {
      LOG_TABLE[EXP_TABLE[i] ] = i;
    }

    var _this = {};

    _this.glog = function(n) {

      if (n < 1) {
        throw 'glog(' + n + ')';
      }

      return LOG_TABLE[n];
    };

    _this.gexp = function(n) {

      while (n < 0) {
        n += 255;
      }

      while (n >= 256) {
        n -= 255;
      }

      return EXP_TABLE[n];
    };

    return _this;
  }();

  //---------------------------------------------------------------------
  // qrPolynomial
  //---------------------------------------------------------------------

  function qrPolynomial(num, shift) {

    if (typeof num.length == 'undefined') {
      throw num.length + '/' + shift;
    }

    var _num = function() {
      var offset = 0;
      while (offset < num.length && num[offset] == 0) {
        offset += 1;
      }
      var _num = new Array(num.length - offset + shift);
      for (var i = 0; i < num.length - offset; i += 1) {
        _num[i] = num[i + offset];
      }
      return _num;
    }();

    var _this = {};

    _this.getAt = function(index) {
      return _num[index];
    };

    _this.getLength = function() {
      return _num.length;
    };

    _this.multiply = function(e) {

      var num = new Array(_this.getLength() + e.getLength() - 1);

      for (var i = 0; i < _this.getLength(); i += 1) {
        for (var j = 0; j < e.getLength(); j += 1) {
          num[i + j] ^= QRMath.gexp(QRMath.glog(_this.getAt(i) ) + QRMath.glog(e.getAt(j) ) );
        }
      }

      return qrPolynomial(num, 0);
    };

    _this.mod = function(e) {

      if (_this.getLength() - e.getLength() < 0) {
        return _this;
      }

      var ratio = QRMath.glog(_this.getAt(0) ) - QRMath.glog(e.getAt(0) );

      var num = new Array(_this.getLength() );
      for (var i = 0; i < _this.getLength(); i += 1) {
        num[i] = _this.getAt(i);
      }

      for (var i = 0; i < e.getLength(); i += 1) {
        num[i] ^= QRMath.gexp(QRMath.glog(e.getAt(i) ) + ratio);
      }

      // recursive call
      return qrPolynomial(num, 0).mod(e);
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // QRRSBlock
  //---------------------------------------------------------------------

  var QRRSBlock = function() {

    var RS_BLOCK_TABLE = [

      // L
      // M
      // Q
      // H

      // 1
      [1, 26, 19],
      [1, 26, 16],
      [1, 26, 13],
      [1, 26, 9],

      // 2
      [1, 44, 34],
      [1, 44, 28],
      [1, 44, 22],
      [1, 44, 16],

      // 3
      [1, 70, 55],
      [1, 70, 44],
      [2, 35, 17],
      [2, 35, 13],

      // 4
      [1, 100, 80],
      [2, 50, 32],
      [2, 50, 24],
      [4, 25, 9],

      // 5
      [1, 134, 108],
      [2, 67, 43],
      [2, 33, 15, 2, 34, 16],
      [2, 33, 11, 2, 34, 12],

      // 6
      [2, 86, 68],
      [4, 43, 27],
      [4, 43, 19],
      [4, 43, 15],

      // 7
      [2, 98, 78],
      [4, 49, 31],
      [2, 32, 14, 4, 33, 15],
      [4, 39, 13, 1, 40, 14],

      // 8
      [2, 121, 97],
      [2, 60, 38, 2, 61, 39],
      [4, 40, 18, 2, 41, 19],
      [4, 40, 14, 2, 41, 15],

      // 9
      [2, 146, 116],
      [3, 58, 36, 2, 59, 37],
      [4, 36, 16, 4, 37, 17],
      [4, 36, 12, 4, 37, 13],

      // 10
      [2, 86, 68, 2, 87, 69],
      [4, 69, 43, 1, 70, 44],
      [6, 43, 19, 2, 44, 20],
      [6, 43, 15, 2, 44, 16],

      // 11
      [4, 101, 81],
      [1, 80, 50, 4, 81, 51],
      [4, 50, 22, 4, 51, 23],
      [3, 36, 12, 8, 37, 13],

      // 12
      [2, 116, 92, 2, 117, 93],
      [6, 58, 36, 2, 59, 37],
      [4, 46, 20, 6, 47, 21],
      [7, 42, 14, 4, 43, 15],

      // 13
      [4, 133, 107],
      [8, 59, 37, 1, 60, 38],
      [8, 44, 20, 4, 45, 21],
      [12, 33, 11, 4, 34, 12],

      // 14
      [3, 145, 115, 1, 146, 116],
      [4, 64, 40, 5, 65, 41],
      [11, 36, 16, 5, 37, 17],
      [11, 36, 12, 5, 37, 13],

      // 15
      [5, 109, 87, 1, 110, 88],
      [5, 65, 41, 5, 66, 42],
      [5, 54, 24, 7, 55, 25],
      [11, 36, 12, 7, 37, 13],

      // 16
      [5, 122, 98, 1, 123, 99],
      [7, 73, 45, 3, 74, 46],
      [15, 43, 19, 2, 44, 20],
      [3, 45, 15, 13, 46, 16],

      // 17
      [1, 135, 107, 5, 136, 108],
      [10, 74, 46, 1, 75, 47],
      [1, 50, 22, 15, 51, 23],
      [2, 42, 14, 17, 43, 15],

      // 18
      [5, 150, 120, 1, 151, 121],
      [9, 69, 43, 4, 70, 44],
      [17, 50, 22, 1, 51, 23],
      [2, 42, 14, 19, 43, 15],

      // 19
      [3, 141, 113, 4, 142, 114],
      [3, 70, 44, 11, 71, 45],
      [17, 47, 21, 4, 48, 22],
      [9, 39, 13, 16, 40, 14],

      // 20
      [3, 135, 107, 5, 136, 108],
      [3, 67, 41, 13, 68, 42],
      [15, 54, 24, 5, 55, 25],
      [15, 43, 15, 10, 44, 16],

      // 21
      [4, 144, 116, 4, 145, 117],
      [17, 68, 42],
      [17, 50, 22, 6, 51, 23],
      [19, 46, 16, 6, 47, 17],

      // 22
      [2, 139, 111, 7, 140, 112],
      [17, 74, 46],
      [7, 54, 24, 16, 55, 25],
      [34, 37, 13],

      // 23
      [4, 151, 121, 5, 152, 122],
      [4, 75, 47, 14, 76, 48],
      [11, 54, 24, 14, 55, 25],
      [16, 45, 15, 14, 46, 16],

      // 24
      [6, 147, 117, 4, 148, 118],
      [6, 73, 45, 14, 74, 46],
      [11, 54, 24, 16, 55, 25],
      [30, 46, 16, 2, 47, 17],

      // 25
      [8, 132, 106, 4, 133, 107],
      [8, 75, 47, 13, 76, 48],
      [7, 54, 24, 22, 55, 25],
      [22, 45, 15, 13, 46, 16],

      // 26
      [10, 142, 114, 2, 143, 115],
      [19, 74, 46, 4, 75, 47],
      [28, 50, 22, 6, 51, 23],
      [33, 46, 16, 4, 47, 17],

      // 27
      [8, 152, 122, 4, 153, 123],
      [22, 73, 45, 3, 74, 46],
      [8, 53, 23, 26, 54, 24],
      [12, 45, 15, 28, 46, 16],

      // 28
      [3, 147, 117, 10, 148, 118],
      [3, 73, 45, 23, 74, 46],
      [4, 54, 24, 31, 55, 25],
      [11, 45, 15, 31, 46, 16],

      // 29
      [7, 146, 116, 7, 147, 117],
      [21, 73, 45, 7, 74, 46],
      [1, 53, 23, 37, 54, 24],
      [19, 45, 15, 26, 46, 16],

      // 30
      [5, 145, 115, 10, 146, 116],
      [19, 75, 47, 10, 76, 48],
      [15, 54, 24, 25, 55, 25],
      [23, 45, 15, 25, 46, 16],

      // 31
      [13, 145, 115, 3, 146, 116],
      [2, 74, 46, 29, 75, 47],
      [42, 54, 24, 1, 55, 25],
      [23, 45, 15, 28, 46, 16],

      // 32
      [17, 145, 115],
      [10, 74, 46, 23, 75, 47],
      [10, 54, 24, 35, 55, 25],
      [19, 45, 15, 35, 46, 16],

      // 33
      [17, 145, 115, 1, 146, 116],
      [14, 74, 46, 21, 75, 47],
      [29, 54, 24, 19, 55, 25],
      [11, 45, 15, 46, 46, 16],

      // 34
      [13, 145, 115, 6, 146, 116],
      [14, 74, 46, 23, 75, 47],
      [44, 54, 24, 7, 55, 25],
      [59, 46, 16, 1, 47, 17],

      // 35
      [12, 151, 121, 7, 152, 122],
      [12, 75, 47, 26, 76, 48],
      [39, 54, 24, 14, 55, 25],
      [22, 45, 15, 41, 46, 16],

      // 36
      [6, 151, 121, 14, 152, 122],
      [6, 75, 47, 34, 76, 48],
      [46, 54, 24, 10, 55, 25],
      [2, 45, 15, 64, 46, 16],

      // 37
      [17, 152, 122, 4, 153, 123],
      [29, 74, 46, 14, 75, 47],
      [49, 54, 24, 10, 55, 25],
      [24, 45, 15, 46, 46, 16],

      // 38
      [4, 152, 122, 18, 153, 123],
      [13, 74, 46, 32, 75, 47],
      [48, 54, 24, 14, 55, 25],
      [42, 45, 15, 32, 46, 16],

      // 39
      [20, 147, 117, 4, 148, 118],
      [40, 75, 47, 7, 76, 48],
      [43, 54, 24, 22, 55, 25],
      [10, 45, 15, 67, 46, 16],

      // 40
      [19, 148, 118, 6, 149, 119],
      [18, 75, 47, 31, 76, 48],
      [34, 54, 24, 34, 55, 25],
      [20, 45, 15, 61, 46, 16]
    ];

    var qrRSBlock = function(totalCount, dataCount) {
      var _this = {};
      _this.totalCount = totalCount;
      _this.dataCount = dataCount;
      return _this;
    };

    var _this = {};

    var getRsBlockTable = function(typeNumber, errorCorrectionLevel) {

      switch(errorCorrectionLevel) {
      case QRErrorCorrectionLevel.L :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];
      case QRErrorCorrectionLevel.M :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];
      case QRErrorCorrectionLevel.Q :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];
      case QRErrorCorrectionLevel.H :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];
      default :
        return undefined;
      }
    };

    _this.getRSBlocks = function(typeNumber, errorCorrectionLevel) {

      var rsBlock = getRsBlockTable(typeNumber, errorCorrectionLevel);

      if (typeof rsBlock == 'undefined') {
        throw 'bad rs block @ typeNumber:' + typeNumber +
            '/errorCorrectionLevel:' + errorCorrectionLevel;
      }

      var length = rsBlock.length / 3;

      var list = [];

      for (var i = 0; i < length; i += 1) {

        var count = rsBlock[i * 3 + 0];
        var totalCount = rsBlock[i * 3 + 1];
        var dataCount = rsBlock[i * 3 + 2];

        for (var j = 0; j < count; j += 1) {
          list.push(qrRSBlock(totalCount, dataCount) );
        }
      }

      return list;
    };

    return _this;
  }();

  //---------------------------------------------------------------------
  // qrBitBuffer
  //---------------------------------------------------------------------

  var qrBitBuffer = function() {

    var _buffer = [];
    var _length = 0;

    var _this = {};

    _this.getBuffer = function() {
      return _buffer;
    };

    _this.getAt = function(index) {
      var bufIndex = Math.floor(index / 8);
      return ( (_buffer[bufIndex] >>> (7 - index % 8) ) & 1) == 1;
    };

    _this.put = function(num, length) {
      for (var i = 0; i < length; i += 1) {
        _this.putBit( ( (num >>> (length - i - 1) ) & 1) == 1);
      }
    };

    _this.getLengthInBits = function() {
      return _length;
    };

    _this.putBit = function(bit) {

      var bufIndex = Math.floor(_length / 8);
      if (_buffer.length <= bufIndex) {
        _buffer.push(0);
      }

      if (bit) {
        _buffer[bufIndex] |= (0x80 >>> (_length % 8) );
      }

      _length += 1;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qrNumber
  //---------------------------------------------------------------------

  var qrNumber = function(data) {

    var _mode = QRMode.MODE_NUMBER;
    var _data = data;

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return _data.length;
    };

    _this.write = function(buffer) {

      var data = _data;

      var i = 0;

      while (i + 2 < data.length) {
        buffer.put(strToNum(data.substring(i, i + 3) ), 10);
        i += 3;
      }

      if (i < data.length) {
        if (data.length - i == 1) {
          buffer.put(strToNum(data.substring(i, i + 1) ), 4);
        } else if (data.length - i == 2) {
          buffer.put(strToNum(data.substring(i, i + 2) ), 7);
        }
      }
    };

    var strToNum = function(s) {
      var num = 0;
      for (var i = 0; i < s.length; i += 1) {
        num = num * 10 + chatToNum(s.charAt(i) );
      }
      return num;
    };

    var chatToNum = function(c) {
      if ('0' <= c && c <= '9') {
        return c.charCodeAt(0) - '0'.charCodeAt(0);
      }
      throw 'illegal char :' + c;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qrAlphaNum
  //---------------------------------------------------------------------

  var qrAlphaNum = function(data) {

    var _mode = QRMode.MODE_ALPHA_NUM;
    var _data = data;

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return _data.length;
    };

    _this.write = function(buffer) {

      var s = _data;

      var i = 0;

      while (i + 1 < s.length) {
        buffer.put(
          getCode(s.charAt(i) ) * 45 +
          getCode(s.charAt(i + 1) ), 11);
        i += 2;
      }

      if (i < s.length) {
        buffer.put(getCode(s.charAt(i) ), 6);
      }
    };

    var getCode = function(c) {

      if ('0' <= c && c <= '9') {
        return c.charCodeAt(0) - '0'.charCodeAt(0);
      } else if ('A' <= c && c <= 'Z') {
        return c.charCodeAt(0) - 'A'.charCodeAt(0) + 10;
      } else {
        switch (c) {
        case ' ' : return 36;
        case '$' : return 37;
        case '%' : return 38;
        case '*' : return 39;
        case '+' : return 40;
        case '-' : return 41;
        case '.' : return 42;
        case '/' : return 43;
        case ':' : return 44;
        default :
          throw 'illegal char :' + c;
        }
      }
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qr8BitByte
  //---------------------------------------------------------------------

  var qr8BitByte = function(data) {

    var _mode = QRMode.MODE_8BIT_BYTE;
    var _data = data;
    var _bytes = qrcode.stringToBytes(data);

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return _bytes.length;
    };

    _this.write = function(buffer) {
      for (var i = 0; i < _bytes.length; i += 1) {
        buffer.put(_bytes[i], 8);
      }
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qrKanji
  //---------------------------------------------------------------------

  var qrKanji = function(data) {

    var _mode = QRMode.MODE_KANJI;
    var _data = data;

    var stringToBytes = qrcode.stringToBytesFuncs['SJIS'];
    if (!stringToBytes) {
      throw 'sjis not supported.';
    }
    !function(c, code) {
      // self test for sjis support.
      var test = stringToBytes(c);
      if (test.length != 2 || ( (test[0] << 8) | test[1]) != code) {
        throw 'sjis not supported.';
      }
    }('\u53cb', 0x9746);

    var _bytes = stringToBytes(data);

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return ~~(_bytes.length / 2);
    };

    _this.write = function(buffer) {

      var data = _bytes;

      var i = 0;

      while (i + 1 < data.length) {

        var c = ( (0xff & data[i]) << 8) | (0xff & data[i + 1]);

        if (0x8140 <= c && c <= 0x9FFC) {
          c -= 0x8140;
        } else if (0xE040 <= c && c <= 0xEBBF) {
          c -= 0xC140;
        } else {
          throw 'illegal char at ' + (i + 1) + '/' + c;
        }

        c = ( (c >>> 8) & 0xff) * 0xC0 + (c & 0xff);

        buffer.put(c, 13);

        i += 2;
      }

      if (i < data.length) {
        throw 'illegal char at ' + (i + 1);
      }
    };

    return _this;
  };

  //=====================================================================
  // GIF Support etc.
  //

  //---------------------------------------------------------------------
  // byteArrayOutputStream
  //---------------------------------------------------------------------

  var byteArrayOutputStream = function() {

    var _bytes = [];

    var _this = {};

    _this.writeByte = function(b) {
      _bytes.push(b & 0xff);
    };

    _this.writeShort = function(i) {
      _this.writeByte(i);
      _this.writeByte(i >>> 8);
    };

    _this.writeBytes = function(b, off, len) {
      off = off || 0;
      len = len || b.length;
      for (var i = 0; i < len; i += 1) {
        _this.writeByte(b[i + off]);
      }
    };

    _this.writeString = function(s) {
      for (var i = 0; i < s.length; i += 1) {
        _this.writeByte(s.charCodeAt(i) );
      }
    };

    _this.toByteArray = function() {
      return _bytes;
    };

    _this.toString = function() {
      var s = '';
      s += '[';
      for (var i = 0; i < _bytes.length; i += 1) {
        if (i > 0) {
          s += ',';
        }
        s += _bytes[i];
      }
      s += ']';
      return s;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // base64EncodeOutputStream
  //---------------------------------------------------------------------

  var base64EncodeOutputStream = function() {

    var _buffer = 0;
    var _buflen = 0;
    var _length = 0;
    var _base64 = '';

    var _this = {};

    var writeEncoded = function(b) {
      _base64 += String.fromCharCode(encode(b & 0x3f) );
    };

    var encode = function(n) {
      if (n < 0) {
        // error.
      } else if (n < 26) {
        return 0x41 + n;
      } else if (n < 52) {
        return 0x61 + (n - 26);
      } else if (n < 62) {
        return 0x30 + (n - 52);
      } else if (n == 62) {
        return 0x2b;
      } else if (n == 63) {
        return 0x2f;
      }
      throw 'n:' + n;
    };

    _this.writeByte = function(n) {

      _buffer = (_buffer << 8) | (n & 0xff);
      _buflen += 8;
      _length += 1;

      while (_buflen >= 6) {
        writeEncoded(_buffer >>> (_buflen - 6) );
        _buflen -= 6;
      }
    };

    _this.flush = function() {

      if (_buflen > 0) {
        writeEncoded(_buffer << (6 - _buflen) );
        _buffer = 0;
        _buflen = 0;
      }

      if (_length % 3 != 0) {
        // padding
        var padlen = 3 - _length % 3;
        for (var i = 0; i < padlen; i += 1) {
          _base64 += '=';
        }
      }
    };

    _this.toString = function() {
      return _base64;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // base64DecodeInputStream
  //---------------------------------------------------------------------

  var base64DecodeInputStream = function(str) {

    var _str = str;
    var _pos = 0;
    var _buffer = 0;
    var _buflen = 0;

    var _this = {};

    _this.read = function() {

      while (_buflen < 8) {

        if (_pos >= _str.length) {
          if (_buflen == 0) {
            return -1;
          }
          throw 'unexpected end of file./' + _buflen;
        }

        var c = _str.charAt(_pos);
        _pos += 1;

        if (c == '=') {
          _buflen = 0;
          return -1;
        } else if (c.match(/^\s$/) ) {
          // ignore if whitespace.
          continue;
        }

        _buffer = (_buffer << 6) | decode(c.charCodeAt(0) );
        _buflen += 6;
      }

      var n = (_buffer >>> (_buflen - 8) ) & 0xff;
      _buflen -= 8;
      return n;
    };

    var decode = function(c) {
      if (0x41 <= c && c <= 0x5a) {
        return c - 0x41;
      } else if (0x61 <= c && c <= 0x7a) {
        return c - 0x61 + 26;
      } else if (0x30 <= c && c <= 0x39) {
        return c - 0x30 + 52;
      } else if (c == 0x2b) {
        return 62;
      } else if (c == 0x2f) {
        return 63;
      } else {
        throw 'c:' + c;
      }
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // gifImage (B/W)
  //---------------------------------------------------------------------

  var gifImage = function(width, height) {

    var _width = width;
    var _height = height;
    var _data = new Array(width * height);

    var _this = {};

    _this.setPixel = function(x, y, pixel) {
      _data[y * _width + x] = pixel;
    };

    _this.write = function(out) {

      //---------------------------------
      // GIF Signature

      out.writeString('GIF87a');

      //---------------------------------
      // Screen Descriptor

      out.writeShort(_width);
      out.writeShort(_height);

      out.writeByte(0x80); // 2bit
      out.writeByte(0);
      out.writeByte(0);

      //---------------------------------
      // Global Color Map

      // black
      out.writeByte(0x00);
      out.writeByte(0x00);
      out.writeByte(0x00);

      // white
      out.writeByte(0xff);
      out.writeByte(0xff);
      out.writeByte(0xff);

      //---------------------------------
      // Image Descriptor

      out.writeString(',');
      out.writeShort(0);
      out.writeShort(0);
      out.writeShort(_width);
      out.writeShort(_height);
      out.writeByte(0);

      //---------------------------------
      // Local Color Map

      //---------------------------------
      // Raster Data

      var lzwMinCodeSize = 2;
      var raster = getLZWRaster(lzwMinCodeSize);

      out.writeByte(lzwMinCodeSize);

      var offset = 0;

      while (raster.length - offset > 255) {
        out.writeByte(255);
        out.writeBytes(raster, offset, 255);
        offset += 255;
      }

      out.writeByte(raster.length - offset);
      out.writeBytes(raster, offset, raster.length - offset);
      out.writeByte(0x00);

      //---------------------------------
      // GIF Terminator
      out.writeString(';');
    };

    var bitOutputStream = function(out) {

      var _out = out;
      var _bitLength = 0;
      var _bitBuffer = 0;

      var _this = {};

      _this.write = function(data, length) {

        if ( (data >>> length) != 0) {
          throw 'length over';
        }

        while (_bitLength + length >= 8) {
          _out.writeByte(0xff & ( (data << _bitLength) | _bitBuffer) );
          length -= (8 - _bitLength);
          data >>>= (8 - _bitLength);
          _bitBuffer = 0;
          _bitLength = 0;
        }

        _bitBuffer = (data << _bitLength) | _bitBuffer;
        _bitLength = _bitLength + length;
      };

      _this.flush = function() {
        if (_bitLength > 0) {
          _out.writeByte(_bitBuffer);
        }
      };

      return _this;
    };

    var getLZWRaster = function(lzwMinCodeSize) {

      var clearCode = 1 << lzwMinCodeSize;
      var endCode = (1 << lzwMinCodeSize) + 1;
      var bitLength = lzwMinCodeSize + 1;

      // Setup LZWTable
      var table = lzwTable();

      for (var i = 0; i < clearCode; i += 1) {
        table.add(String.fromCharCode(i) );
      }
      table.add(String.fromCharCode(clearCode) );
      table.add(String.fromCharCode(endCode) );

      var byteOut = byteArrayOutputStream();
      var bitOut = bitOutputStream(byteOut);

      // clear code
      bitOut.write(clearCode, bitLength);

      var dataIndex = 0;

      var s = String.fromCharCode(_data[dataIndex]);
      dataIndex += 1;

      while (dataIndex < _data.length) {

        var c = String.fromCharCode(_data[dataIndex]);
        dataIndex += 1;

        if (table.contains(s + c) ) {

          s = s + c;

        } else {

          bitOut.write(table.indexOf(s), bitLength);

          if (table.size() < 0xfff) {

            if (table.size() == (1 << bitLength) ) {
              bitLength += 1;
            }

            table.add(s + c);
          }

          s = c;
        }
      }

      bitOut.write(table.indexOf(s), bitLength);

      // end code
      bitOut.write(endCode, bitLength);

      bitOut.flush();

      return byteOut.toByteArray();
    };

    var lzwTable = function() {

      var _map = {};
      var _size = 0;

      var _this = {};

      _this.add = function(key) {
        if (_this.contains(key) ) {
          throw 'dup key:' + key;
        }
        _map[key] = _size;
        _size += 1;
      };

      _this.size = function() {
        return _size;
      };

      _this.indexOf = function(key) {
        return _map[key];
      };

      _this.contains = function(key) {
        return typeof _map[key] != 'undefined';
      };

      return _this;
    };

    return _this;
  };

  var createDataURL = function(width, height, getPixel) {
    var gif = gifImage(width, height);
    for (var y = 0; y < height; y += 1) {
      for (var x = 0; x < width; x += 1) {
        gif.setPixel(x, y, getPixel(x, y) );
      }
    }

    var b = byteArrayOutputStream();
    gif.write(b);

    var base64 = base64EncodeOutputStream();
    var bytes = b.toByteArray();
    for (var i = 0; i < bytes.length; i += 1) {
      base64.writeByte(bytes[i]);
    }
    base64.flush();

    return 'data:image/gif;base64,' + base64;
  };

  //---------------------------------------------------------------------
  // returns qrcode function.

  return qrcode;
}();

// multibyte support
!function() {

  qrcode.stringToBytesFuncs['UTF-8'] = function(s) {
    // http://stackoverflow.com/questions/18729405/how-to-convert-utf8-string-to-byte-array
    function toUTF8Array(str) {
      var utf8 = [];
      for (var i=0; i < str.length; i++) {
        var charcode = str.charCodeAt(i);
        if (charcode < 0x80) utf8.push(charcode);
        else if (charcode < 0x800) {
          utf8.push(0xc0 | (charcode >> 6),
              0x80 | (charcode & 0x3f));
        }
        else if (charcode < 0xd800 || charcode >= 0xe000) {
          utf8.push(0xe0 | (charcode >> 12),
              0x80 | ((charcode>>6) & 0x3f),
              0x80 | (charcode & 0x3f));
        }
        // surrogate pair
        else {
          i++;
          // UTF-16 encodes 0x10000-0x10FFFF by
          // subtracting 0x10000 and splitting the
          // 20 bits of 0x0-0xFFFFF into two halves
          charcode = 0x10000 + (((charcode & 0x3ff)<<10)
            | (str.charCodeAt(i) & 0x3ff));
          utf8.push(0xf0 | (charcode >>18),
              0x80 | ((charcode>>12) & 0x3f),
              0x80 | ((charcode>>6) & 0x3f),
              0x80 | (charcode & 0x3f));
        }
      }
      return utf8;
    }
    return toUTF8Array(s);
  };

}();

(function (factory) {
  if (typeof define === 'function' && define.amd) {
      define([], factory);
  } else if (typeof exports === 'object') {
      module.exports = factory();
  }
}(function () {
    return qrcode;
}));

'use strict';
const $=id=>document.getElementById(id);
let token=location.hash.slice(1)||sessionStorage.getItem('vpn-local-token')||'';
if(location.hash){sessionStorage.setItem('vpn-local-token',token);history.replaceState(null,'',location.pathname);}
let backupRows=[],backupsLoading=false,currentConfig=null,currentConfigLoading=false,currentConfigDirty=false;
let page=1,selected={action:'install',routing:'split',auth:'password'},pins={},jobId='',pollTimer=null,running=false,sshAvailable=false,platform='macos';
const actionNames={install:'Установить',fresh:'Установить заново',resume:'Обновить/Восстановить',verify:'Проверить VPN',check:'Проверить серверы',remove:'Удалить'};
const routeNames={split:'Раздельные маршруты',full_mixed:'Весь трафик через VPN',full_nl:'Весь трафик через зарубежный сервер'};
const authNames={password:'Сертификат + логин и пароль',certificate:'Только индивидуальный сертификат'};
function setInstallConnection(connected){const button=$('modeInstall');button.classList.toggle('server-connected',connected===true);button.querySelector('.mode-connection-dot').setAttribute('aria-label',connected?'Подключение установки/обновления проверено':'Нет подключения установки/обновления');syncWorkspaceConnectionBadge();}
function message(text){$('error').textContent=text;$('error').classList.toggle('hidden',!text);if(text)$('error').scrollIntoView({behavior:'smooth',block:'center'});}
function choiceGroup(target,key,items){
 const box=$(target);box.replaceChildren();
 for(const [value,title,description] of items){const b=document.createElement('button');b.type='button';b.className='choice'+(selected[key]===value?' selected':'');b.setAttribute('aria-pressed',selected[key]===value);const strong=document.createElement('strong');strong.textContent=title;const p=document.createElement('p');p.textContent=description;b.append(strong,p);b.onclick=()=>{if(running)return;const previous=selected[key];selected[key]=value;if(key!=='action'&&currentConfig)currentConfigDirty=true;choiceGroup(target,key,items);$('confirmation').checked=false;updateRouteNotice();updateRestoreOptions();scheduleSession();if(key==='action'&&value==='resume'&&$('ruHost').value&&$('nlHost').value){if(previous!==value)currentConfigDirty=false;loadCurrentConfiguration(true);}};box.append(b);}
}
let sshAliasCatalog=[];
function aliasHTML(value){return String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function sshAliasOptions(selected=''){return '<option value="">Выбрать SSH-алиас</option>'+sshAliasCatalog.map(a=>`<option value="${aliasHTML(a.alias)}" ${a.alias===selected?'selected':''} ${a.disabled?'disabled':''}>${aliasHTML(a.alias)} — ${aliasHTML(a.host)}${a.disabled?' · '+aliasHTML(a.reason):''}</option>`).join('');}
function sshAliasSelect(scope,role,selected=''){return `<select class="host-alias-select" data-alias-scope="${scope}" data-alias-role="${role}" aria-label="Выбрать SSH-алиас: ${role==='ru'?'российский':'зарубежный'} сервер" title="Выбрать SSH-алиас">${sshAliasOptions(selected)}</select>`;}
function serverCard(role,title,tag){
 return `<div class="panel"><div class="panel-top"><span class="tag ${role==='nl'?'green':''}">${tag}</span><span class="muted">SSH</span></div><h2>${title}</h2><div class="fields"><div class="input-row"><label>IP-адрес<div class="host-picker"><input id="${role}Host" placeholder="Публичный IPv4 или алиас" autocomplete="off">${sshAliasSelect('install',role)}</div></label><label>SSH-порт<input id="${role}Port" type="number" min="1" max="65535" value="22"></label></div><label>Пользователь<input id="${role}User" value="root" readonly></label><label>Способ подключения<select id="${role}Method"><option value="password">Пароль</option><option value="key">Вставить приватный SSH-ключ</option><option value="local-key">Мой локальный ключ / скопировать на сервер</option></select></label><label id="${role}PasswordRow">Пароль SSH<input id="${role}Password" type="password" autocomplete="off" placeholder="Только в текущем сеансе"></label><div id="${role}KeyRow" class="hidden"><label>Содержимое приватного SSH-ключа<textarea id="${role}Key" spellcheck="false" placeholder="Вставьте приватный ключ" autocomplete="off"></textarea></label><label>Пароль ключа <small>если задан</small><input id="${role}Passphrase" type="password" autocomplete="off"></label></div><div id="${role}LocalRow" class="hidden local-key-box"><label>Путь к приватному ключу на этом компьютере<input id="${role}KeyPath" value="~/.ssh/id_ed25519" autocomplete="off"></label><label>Пароль ключа <small>если задан</small><input id="${role}LocalPassphrase" type="password" autocomplete="off"></label><p>Если публичный ключ ещё не установлен на сервере, скопируйте команду и выполните её на своём компьютере. SSH запросит пароль сервера.</p><div class="key-actions"><label>Система для команды<select id="${role}CommandOS"><option value="macos">macOS</option><option value="linux">Linux</option><option value="windows">Windows · PowerShell</option></select></label><button id="${role}MakeCommand" type="button" class="secondary">Показать команду</button></div><pre id="${role}CopyCommand" class="hidden key-command"></pre><button id="${role}CopyButton" type="button" class="secondary hidden">Скопировать команду</button><details id="${role}Fallback" class="hidden"><summary>Если ssh-copy-id не установлен</summary><pre id="${role}FallbackCommand" class="key-command"></pre><button id="${role}FallbackCopy" type="button" class="secondary">Скопировать альтернативу</button></details><p>На сервер копируется только публичный файл .pub. Для подключения приложение прочитает приватный ключ локально, не загружая его на сервер.</p></div></div></div>`;
}
$('serverCards').innerHTML=serverCard('ru','Российский сервер','RU')+serverCard('nl','Зарубежный сервер','EU');
const actionItems=[['install','Установить','Новая установка на двух серверах'],['fresh','Установить заново','Резервная копия, удаление и новая установка'],['resume','Обновить/Восстановить','Изменение текущих настроек или восстановление из архива'],['verify','Проверить VPN','Службы, порты, маршруты и GRE/IPsec — без изменения настроек'],['check','Проверить серверы','Только прочитать состояние'],['remove','Удалить','Удалить компоненты VPN на обоих серверах']];
choiceGroup('actions','action',actionItems);
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
function invalidatePins(){setInstallConnection(false);if(currentConfig&&currentConfig.pair!==currentPairKey()){currentConfig=null;$('currentConfigStatus').textContent='Серверы изменены. Загрузите текущие настройки заново.';}pins={};resetBackupList();$('sshTrustStatus').textContent='SSH-ключи будут автоматически проверены при запуске операции. Для новых серверов потребуется подтверждение доверия.';}
for(const role of ['ru','nl']){
 $(role+'Method').onchange=()=>{const key=$(role+'Method').value==='key';$(role+'KeyRow').classList.toggle('hidden',!key);$(role+'LocalRow').classList.toggle('hidden',$(role+'Method').value!=='local-key');$(role+'PasswordRow').classList.toggle('hidden',$(role+'Method').value!=='password');invalidatePins();};
 for(const field of ['Host','Port','KeyPath'])$(role+field).addEventListener('input',()=>{if(field==='Host'){$(role+'Host').dataset.sshAlias='';const menu=document.querySelector('[data-alias-scope=install][data-alias-role='+role+']');if(menu)menu.value='';}invalidatePins();clearCommand(role);});
 $(role+'CommandOS').onchange=()=>clearCommand(role);
 $(role+'MakeCommand').onclick=()=>makeCommand(role);
 $(role+'CopyButton').onclick=()=>copyCommand(role,false);
 $(role+'FallbackCopy').onclick=()=>copyCommand(role,true);
}
function resetBackupList(){
 if(!$('restoreBackup'))return;backupRows=[];$('restoreBackup').replaceChildren(new Option('Обновить текущую конфигурацию',''));$('backupStatus').textContent='После ввода данных серверов загрузите список архивов.';
}
function currentPairKey(){return ['ru','nl'].map(r=>$(r+'Host').value+':'+$(r+'Port').value).join('|');}
function applyCurrentConfiguration(config,automatic=false){
 window.vpnaiLimits.syncFromServer(config.limits,config.limits_error,true);
 currentConfig={...config,pair:currentPairKey()};currentConfigDirty=false;
 selected.routing=config.config.routing_mode;selected.auth=config.config.auth_mode;$('vpnPort').value=config.config.ovpn_port;
 $('ruRoutes').value=config.ru_routes.join('\n');$('euRoutes').value=config.eu_routes.join('\n');
 for(const id of ['ruRoutes','euRoutes'])$(id).oninput();
 document.querySelectorAll('#routes .choice').forEach((b,i)=>{const active=['split','full_mixed','full_nl'][i]===selected.routing;b.classList.toggle('selected',active);b.setAttribute('aria-pressed',active);});
 document.querySelectorAll('#authChoices .choice').forEach((b,i)=>{const active=['password','certificate'][i]===selected.auth;b.classList.toggle('selected',active);b.setAttribute('aria-pressed',active);});
 $('currentConfigStatus').textContent=config.legacy?'Настройки прочитаны из действующего VPN. Пользователей: '+config.user_count+'. Для этой установки доступна смена входа и выбор DNS без переустановки. Пользователи, сертификаты, порт и маршруты сохраняются.':'Настройки и списки получены с сервера. Пользователей: '+config.user_count+'. Теперь можно внести изменения.';
 $('routesSourceStatus').textContent='Списки получены с сервера: RU — '+config.ru_routes.length+', RU-EU — '+config.eu_routes.length+'.';
 if(config.legacy)$('updatePackages').value='no';
 window.vpnaiDNSPreview.syncFromServer(config.dns,automatic,config.dns_error);
 updateRouteNotice();updateRestoreOptions();scheduleSession();
}
async function loadCurrentConfiguration(automatic=false){
 if(automatic&&currentConfigDirty&&currentConfig){$('currentConfigStatus').textContent='Показаны загруженные настройки с вашими изменениями. Автоматическое чтение не сбрасывает введённые данные; кнопка загрузки перечитает их с сервера.';return;}
 if(running||currentConfigLoading)return;currentConfigLoading=true;$('restoreBackup').value='';$('confirmation').checked=false;message('');lockForm(true);
 $('currentConfigStatus').textContent='Читаем текущие настройки и списки с сервера…';const requestedPair=currentPairKey();
 try{const d={...data(),dns:undefined,restore_backup:'',action:'check',ru_routes:'',eu_routes:'',initial_user:'user1',comment:''};if(!(await prepareSSH(d)))return;const result=await api('/api/update-config',d);if(requestedPair!==currentPairKey()||selected.action!=='resume')return;applyCurrentConfiguration(result,automatic);}
 catch(e){message(e.message);$('currentConfigStatus').textContent='Не удалось загрузить настройки. Обновление не будет запущено без актуальной конфигурации.';}
 finally{currentConfigLoading=false;lockForm(false);}
}
$('loadCurrentConfig').onclick=()=>loadCurrentConfiguration(false);
for(const id of ['ruRoutes','euRoutes','vpnPort'])$(id).addEventListener('input',()=>{if(currentConfig)currentConfigDirty=true;});
function updateRestoreOptions(){
 if(!$('restoreOptions'))return;$('restoreOptions').classList.toggle('hidden',selected.action!=='resume');
 const archive=selected.action==='resume'&&!!$('restoreBackup').value;
 const legacy=selected.action==='resume'&&!archive&&currentConfig?.legacy===true;
 const existing=legacy||selected.action==='resume'&&!archive&&currentConfig&&currentConfig.user_count>0;
 $('initialUser').disabled=running||existing;$('comment').disabled=running||existing;
 $('initialUserHint').textContent=existing?'Существующие пользователи будут сохранены. Новый пользователь не создаётся.':'Пользователь создаётся при установке или если при обновлении на сервере нет пользователей.';
 for(const id of ['ruRoutes','euRoutes']){$(id).disabled=running||archive;$(id).readOnly=legacy;}
 $('vpnPort').disabled=running||archive||legacy;$('updatePackages').disabled=running||legacy;
 $('installationDNSPreview').classList.remove('hidden');
 document.querySelectorAll('#routes .choice').forEach(button=>button.disabled=running||archive||legacy);
 document.querySelectorAll('#authChoices .choice').forEach(button=>button.disabled=running||archive);
}
async function loadBackups(){
 if(backupsLoading||running)return;message('');backupsLoading=true;$('loadBackups').disabled=true;lockForm(true);
 try{
  const d={...data(),restore_backup:'',ru_routes:'',eu_routes:'',initial_user:'user1',comment:'',routing:'split',auth:'password',vpn_port:1194};
  if(!(await prepareSSH(d)))return;
  if(!currentConfig){try{applyCurrentConfiguration(await api('/api/update-config',d));}catch(e){$('currentConfigStatus').textContent=e.message;}}
  const response=await api('/api/backups',d);resetBackupList();backupRows=response.backups;
  for(const item of backupRows){
   const time=item.created?new Date(item.created).toLocaleString():new Date(item.mtime*1000).toLocaleString();
   const option=new Option(item.name+' — '+time+(item.available?'':' — недоступен'),item.name);option.disabled=!item.available;$('restoreBackup').append(option);
  }
  $('backupStatus').textContent=backupRows.length?'Доступно проверенных пар: '+backupRows.filter(item=>item.available).length+'. Архивы без однозначной пары выбрать нельзя.':'Архивы нового парного формата на российском сервере не найдены.';
 }catch(error){message(error.message);$('backupStatus').textContent='Не удалось загрузить архивы. Проверьте доступ к обоим серверам.';}
 finally{backupsLoading=false;$('loadBackups').disabled=false;lockForm(false);}
}
$('loadBackups').onclick=loadBackups;
$('restoreBackup').onchange=()=>{
 const item=backupRows.find(row=>row.name===$('restoreBackup').value);$('confirmation').checked=false;
 if(item){
  const values=item.settings||{};
  if(values.routing_mode)selected.routing=values.routing_mode;if(values.auth_mode)selected.auth=values.auth_mode;
  for(const id of ['ruRoutes','euRoutes']){$(id).value='';$(id).oninput();}
  if(values.ovpn_port)$('vpnPort').value=values.ovpn_port;if(values.initial_user)$('initialUser').value=values.initial_user;
  document.querySelectorAll('#routes .choice').forEach((button,index)=>{const active=['split','full_mixed','full_nl'][index]===selected.routing;button.classList.toggle('selected',active);button.setAttribute('aria-pressed',active);});
  document.querySelectorAll('#authChoices .choice').forEach((button,index)=>{const active=(index?'certificate':'password')===selected.auth;button.classList.toggle('selected',active);button.setAttribute('aria-pressed',active);});
  $('backupStatus').textContent='Соответствующий архив на зарубежном сервере: '+item.counterpart+'. Режимы и порт подставлены из копии.';updateRouteNotice();
 }else{currentConfig=null;loadCurrentConfiguration();}
 updateRestoreOptions();scheduleSession();if(page===3)review();
};
function applyMode(){$('sshMissing').classList.toggle('hidden',sshAvailable);invalidatePins();updateRestoreOptions();if(page===3)review();}
for(const [id,countId] of [['ruRoutes','ruCount'],['euRoutes','euCount']])$(id).oninput=()=>{$(countId).textContent=$(id).value.split('\n').filter(x=>x.split('#')[0].trim()).length+' записей';};
function data(){
 const d={connection_limit:window.vpnaiLimits.installation(),update_revision:currentConfig?.revision||'',update_user_count:currentConfig?.user_count||0,update_loaded_pair:currentConfig?.pair||'',update_legacy:currentConfig?.legacy===true,update_dirty:currentConfigDirty,restore_backup:selected.action==='resume'?$('restoreBackup').value:'',action:selected.action,routing:selected.routing,auth:selected.auth,initial_user:selected.action==='resume'&&!$('restoreBackup').value&&currentConfig?.user_count>0?'user1':$('initialUser').value,comment:$('comment').value,vpn_port:$('vpnPort').value,update_packages:$('updatePackages').value==='yes',ru_routes:$('ruRoutes').value,eu_routes:$('euRoutes').value,confirmed:$('confirmation').checked,dns:window.vpnaiDNSPreview.installation(),eu_ssh:(window.vpnaiUnified&&window.vpnaiUnified.eu_ssh)||'direct',eu_target:(window.vpnaiUnified&&window.vpnaiUnified.eu_target)||'public'};
 for(const role of ['ru','nl'])d[role]={host:$(role+'Host').value,alias:$(role+'Host').dataset.sshAlias||'',port:$(role+'Port').value,user:'root',method:$(role+'Method').value,password:$(role+'Password').value,key:$(role+'Key').value,key_path:$(role+'KeyPath').value,passphrase:$(role+($(role+'Method').value==='local-key'?'LocalPassphrase':'Passphrase')).value,fingerprint:pins[role]||''};return d;
}
async function api(path,payload){const options={headers:{'X-Local-Token':token}};if(payload!==undefined){options.method='POST';options.headers['Content-Type']='application/json';options.body=JSON.stringify(payload);}const r=await fetch(path,options);const answer=await r.json();if(!r.ok)throw Error(answer.error||'Ошибка запроса.');return answer;}
function show(n){if(n<1){window.dispatchEvent(new Event('vpnai-open-connection'));return;}if(running&&n!==3)return;page=n;message('');document.querySelectorAll('.page').forEach(el=>el.classList.toggle('hidden',Number(el.dataset.page)!==n));document.querySelectorAll('.nav').forEach(el=>el.classList.toggle('active',Number(el.dataset.page)===n));if(n===3)review();if((n===1||n===2)&&selected.action==='resume'&&!$('restoreBackup').value&&$('ruHost').value&&$('nlHost').value&&!running)loadCurrentConfiguration(true);window.scrollTo({top:0,behavior:'smooth'});}
document.querySelectorAll('.nav').forEach(b=>b.onclick=()=>show(Number(b.dataset.page)));
document.querySelectorAll('.next').forEach(b=>b.onclick=()=>show(Math.min(3,page+1)));
document.querySelectorAll('.back').forEach(b=>b.onclick=()=>show(Math.max(0,page-1)));
function review(){const d=data();const rows=[['Максимум подключений',window.vpnaiLimits.installation()||'Без ограничений'],['Российский сервер',d.ru.host||'Не указан'],['Зарубежный сервер',d.nl.host||'Не указан'],['Действие',actionNames[d.action]],...(d.action==='resume'?[['Источник',d.restore_backup||'Обновить текущую конфигурацию']]:[]),['Маршрутизация',routeNames[d.routing]],['Авторизация',authNames[d.auth]],['Обновить пакеты ОС',d.update_packages?'Да':'Нет'],['Пользователь',d.action==='resume'&&!d.restore_backup&&currentConfig?.user_count>0?'Существующие сохраняются; новый не создаётся':d.initial_user],['Список RU',d.restore_backup?'Из выбранного архива':d.ru_routes.split('\n').filter(x=>x.split('#')[0].trim()).length+' записей'],['Список RU-EU',d.restore_backup?'Из выбранного архива':d.eu_routes.split('\n').filter(x=>x.split('#')[0].trim()).length+' записей']];rows.push(['DNS для VPN-клиентов',d.restore_backup?'Из резервной копии':window.vpnaiDNSPreview.description()]);$('summary').replaceChildren();for(const [title,value] of rows){const item=document.createElement('div');item.className='summary-item';const k=document.createElement('small');k.textContent=title;const v=document.createElement('strong');v.textContent=value;item.append(k,v);$('summary').append(item);}$('destructive').classList.toggle('hidden',!(['fresh','remove'].includes(d.action)||!!d.restore_backup));$('start').textContent=actionNames[d.action];$('destructiveDescription').textContent=d.restore_backup?'Пользователи, ключи, профили и маршруты будут заменены содержимым выбранной пары архивов. Перед заменой текущее состояние обоих серверов будет сохранено в защитные копии. На зарубежном сервере будет использован автоматически проверенный соответствующий архив.':d.action==='fresh'?'На обоих серверах будут созданы закрытые резервные копии, удалены компоненты текущего VPN, его пользователи, профили и маршруты, затем выполнена новая установка с параметрами формы.':'На обоих серверах будут созданы закрытые резервные копии и удалены компоненты текущего VPN, его пользователи, профили и маршруты. Системные пакеты и резервные архивы сохранятся. Новая установка выполняться не будет.';$('reviewSubtitle').textContent='Будут использованы два указанных сервера. Данные подключения хранятся только в памяти текущего запуска.';if(currentConfig?.legacy&&d.action==='resume'&&!d.restore_backup)$('reviewSubtitle').textContent='Будет применён выбранный способ входа и DNS, если вы включили их в обновление. Пользователи, сертификаты, порт и маршруты сохранятся; компоненты VPN не переустанавливаются.';}

function lockForm(lock){window.dispatchEvent(new CustomEvent('vpnai-installer-busy',{detail:lock}));running=lock;document.querySelectorAll('input,select,textarea,.choice,.nav').forEach(el=>el.disabled=lock);$('runControls').classList.toggle('hidden',lock||!!jobId);updateRestoreOptions();}
async function prepareSSH(d){
 const prepared=await api('/api/ssh/prepare',d);
 if(prepared.confirmation_required){
  const unknown=prepared.servers.filter(s=>!s.known);
  const description=unknown.map(s=>(s.role==='ru'?'Российский':'Зарубежный')+' сервер '+s.host+':'+s.port+'\n'+s.fingerprint).join('\n\n');
  const accepted=window.confirm('Первое подключение: доверять этим SSH-ключам?\n\n'+description+'\n\nПри возможности сверьте отпечатки через консоль хостинга. Без независимой сверки первое подключение основано на доверии полученному ключу. Пароль пока не передавался.\n\nОК — доверять ключам до закрытия приложения и продолжить; Отмена — остановиться.');
  if(!accepted){message('Подключение отменено. Новые SSH-ключи не приняты, пароль серверам не передавался.');return false;}
  pins=(await api('/api/ssh/confirm',{confirmation_token:prepared.confirmation_token,accept:true})).fingerprints;
 }else pins=prepared.fingerprints;
 for(const role of ['ru','nl'])d[role].fingerprint=pins[role];
 $('sshTrustStatus').textContent='SSH-ключи проверены. При соединении они будут проверены повторно.';
 return true;
}
$('start').onclick=async()=>{
 message('');const d=data();if(currentConfig?.legacy&&d.action==='resume'&&!d.restore_backup){if(!confirm('Применить способ входа и выбранные DNS без переустановки VPN? Если DNS не включён в обновление, он сохранится. Пользователи, сертификаты и маршруты сохранятся. Активные подключения прервутся. После операции нужно импортировать обновлённые профили и переподключить устройства.'))return;d.legacy_confirmed=true;}lockForm(true);$('start').disabled=true;
 try{
  if(d.action==='resume'&&!d.restore_backup&&!currentConfig)throw Error('Сначала загрузите текущие настройки сервера.');
  if((['fresh','remove'].includes(d.action)||d.restore_backup)&&!d.confirmed)throw Error('Установите флажок «Я подтверждаю» после прочтения описания.');
  await api('/api/session',d);
  if(!(await prepareSSH(d)))return;
  const j=await api('/api/jobs',d);jobId=j.id;
  $('progressPanel').classList.remove('hidden');$('result').classList.add('hidden');poll();
 }catch(e){message(e.message);}
 finally{if(!jobId)lockForm(false);$('start').disabled=false;}
};

function reportSummary(r){
 if(!r.servers)return;
 const rows=[['Российский сервер',r.servers.ru],['Зарубежный сервер',r.servers.nl],['Действие',actionNames[r.action]],...(r.archive_restore?[['Архив RU',r.archive_restore.ru_archive],['Архив зарубежного сервера',r.archive_restore.foreign_archive]]:[]),['Маршрутизация',(routeNames[r.routing]||'Не определена — см. журнал')],['Авторизация',(authNames[r.auth]||'Не определена — см. журнал')],['Обновить пакеты ОС',r.update_packages?'Да':'Нет'],['Пользователь',r.users_preserved?'Сохранено пользователей: '+r.users_preserved:r.initial_user||'—'],['Список RU',r.lists_from_server?'Сохранённый на сервере':(r.lists?.ru?.length||0)+' записей'],['Список RU-EU',r.lists_from_server?'Сохранённый на сервере':(r.lists?.eu?.length||0)+' записей']];
 $('summary').replaceChildren();for(const [title,value] of rows){const item=document.createElement('div');item.className='summary-item';const k=document.createElement('small');k.textContent=title;const v=document.createElement('strong');v.textContent=value;item.append(k,v);$('summary').append(item);}
}
async function poll(){clearTimeout(pollTimer);try{const j=await api('/api/jobs/'+jobId);setInstallConnection(j.ssh_connected&&j.status!=='error'&&j.status!=='cancelled');reportSummary(j.report);$('progressPanel').classList.remove('hidden');$('phase').textContent=j.phase;$('percentage').textContent=j.progress+'%';$('progressBar').style.width=j.progress+'%';$('log').replaceChildren();for(const e of j.events){const p=document.createElement('p');const t=document.createElement('time');t.textContent=e.time;const span=document.createElement('span');span.textContent=e.message;p.append(t,span);$('log').append(p);}$('log').scrollTop=$('log').scrollHeight;const active=j.status==='running';lockForm(active);$('cancel').classList.toggle('hidden',!active);$('download').classList.toggle('hidden',!j.download);$('download').textContent='Скачать профили';$('report').classList.toggle('hidden',active);$('again').classList.toggle('hidden',active);$('runBadge').textContent=active?'В ПРОЦЕССЕ':j.status==='success'?'ЗАВЕРШЕНО':j.status==='cancelled'?'ОСТАНОВЛЕНО':'ОШИБКА';if(!active){$('result').classList.remove('hidden');$('result').classList.toggle('error-result',j.status==='error');$('result').textContent=j.status==='success'?(j.report.notice||'Операция завершена.'):(j.events[j.events.length-1]?.message||'Операция остановлена.');}else pollTimer=setTimeout(poll,700);}catch(e){lockForm(false);message(e.message);$('again').classList.remove('hidden');}}
$('cancel').onclick=async()=>{try{await api('/api/jobs/'+jobId+'/cancel',{});$('cancel').textContent='Ожидается завершение текущего этапа…';$('cancel').disabled=true;}catch(e){message(e.message);}};
async function download(suffix){try{const r=await fetch('/api/jobs/'+jobId+'/'+suffix,{headers:{'X-Local-Token':token}});if(!r.ok){const e=await r.json();throw Error(e.error);}const blob=await r.blob(),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=suffix==='report'?'vpn-report.json':'openvpn-all.zip';a.click();setTimeout(()=>URL.revokeObjectURL(url),10000);}catch(e){message(e.message);}}
$('download').onclick=()=>download('download');$('report').onclick=()=>download('report');
$('again').onclick=()=>{jobId='';clearTimeout(pollTimer);lockForm(false);$('progressPanel').classList.add('hidden');$('runControls').classList.remove('hidden');$('cancel').disabled=false;$('cancel').textContent='Остановить после текущего этапа';$('confirmation').checked=false;show(1);applyMode();};
let sessionReady=false,saveTimer=null,heartbeat=null,terminated=false;
function clearSessionView(){
 setInstallConnection(false);window.dispatchEvent(new Event('vpnai-session-ended'));terminated=true;sessionReady=false;clearTimeout(saveTimer);clearTimeout(pollTimer);clearInterval(heartbeat);
 for(const role of ['ru','nl'])for(const suffix of ['Host','Password','Key','Passphrase','LocalPassphrase'])$(role+suffix).value='';
 for(const role of ['ru','nl']){$(role+'KeyPath').value='~/.ssh/id_ed25519';$(role+'Port').value='22';}
 for(const id of ['ruRoutes','euRoutes','comment'])$(id).value='';
 $('initialUser').value='user1';$('confirmation').checked=false;pins={};jobId='';
 $('summary').replaceChildren();$('log').replaceChildren();$('result').textContent='';
 document.querySelectorAll('button,input,select,textarea').forEach(el=>el.disabled=true);
}
window.addEventListener('vpnai-dns-draft',event=>{if(currentConfig&&!event.detail?.read)currentConfigDirty=true;scheduleSession();});
function scheduleSession(){if(!sessionReady)return;clearTimeout(saveTimer);saveTimer=setTimeout(()=>api('/api/session',data()).catch(()=>{}),200);}
function restoreSession(saved){
 if(terminated)return;
 for(const key of ['action','routing','auth'])if(saved[key])selected[key]=saved[key];
 for(const [key,id] of Object.entries({initial_user:'initialUser',comment:'comment',vpn_port:'vpnPort',ru_routes:'ruRoutes',eu_routes:'euRoutes'}))if(saved[key]!==undefined)$(id).value=saved[key];
 if(saved.update_packages!==undefined)$('updatePackages').value=saved.update_packages?'yes':'no';
 for(const role of ['ru','nl']){
  const values=saved[role]||{};$(role+'Host').dataset.sshAlias=values.alias||'';const menu=document.querySelector('[data-alias-scope=install][data-alias-role='+role+']');if(menu)menu.value=values.alias||'';
  for(const [key,suffix] of Object.entries({host:'Host',port:'Port',method:'Method',password:'Password',key:'Key',key_path:'KeyPath'}))if(values[key]!==undefined)$(role+suffix).value=values[key];
  if(values.passphrase!==undefined)$(role+($(role+'Method').value==='local-key'?'LocalPassphrase':'Passphrase')).value=values.passphrase;
  $(role+'Method').onchange();
 }
 choiceGroup('actions','action',actionItems);document.querySelectorAll('#routes .choice').forEach((b,i)=>{const keys=['split','full_mixed','full_nl'];b.classList.toggle('selected',keys[i]===selected.routing);b.setAttribute('aria-pressed',keys[i]===selected.routing);});
 document.querySelectorAll('#authChoices .choice').forEach((b,i)=>{const key=i?'certificate':'password';b.classList.toggle('selected',key===selected.auth);b.setAttribute('aria-pressed',key===selected.auth);});
 window.vpnaiLimits.restore(saved.connection_limit);if(saved.update_revision&&saved.update_loaded_pair===currentPairKey()){currentConfig={revision:saved.update_revision,user_count:saved.update_user_count||0,pair:saved.update_loaded_pair,legacy:saved.update_legacy===true};currentConfigDirty=saved.update_dirty===true;$('currentConfigStatus').textContent='Загруженные настройки и изменения восстановлены из текущего сеанса.';}for(const id of ['ruRoutes','euRoutes'])$(id).oninput();updateRouteNotice();updateRestoreOptions();
}
document.addEventListener('input',event=>{if(event.target.id!=='confirmation')$('confirmation').checked=false;scheduleSession();});
document.addEventListener('change',()=>scheduleSession());
(async()=>{
 try{
  const info=await api('/api/info');setInstallConnection(info.install_connected);sshAvailable=info.ssh_available;platform=info.platform;
  for(const r of ['ru','nl'])$(r+'CommandOS').value=platform;
  const saved=await api('/api/session');if(terminated)return;restoreSession(saved);window.vpnaiDNSPreview.restore(saved.dns);sessionReady=true;applyMode();window.vpnaiUnified.installerReady=true;window.vpnaiUnified.installDraft={ru:saved.ru,nl:saved.nl};window.dispatchEvent(new Event('vpnai-install-draft-ready'));
  if(info.running.length)jobId=info.running[0];
  if(jobId){show(3);poll();}
  heartbeat=setInterval(async()=>{try{const info=await api('/api/info');setInstallConnection(info.install_connected);}catch(e){clearSessionView();message('Приложение закрыто или недоступно. Данные подключения очищены.');}},5000);
 }catch(e){message(e.message);}
})();


window.addEventListener('vpnai-shared-servers',event=>{
 if(running)return;
 let changed=false;
 for(const role of ['ru','nl']){
  const values=event.detail[role]||{};
  for(const [key,suffix] of Object.entries({host:'Host',port:'Port',user:'User',method:'Method',password:'Password',key:'Key',key_path:'KeyPath',passphrase:'Passphrase'})){
   if(values[key]!==undefined&&$(role+suffix).value!==String(values[key])){$(role+suffix).value=values[key];changed=true;}
  }
  if(values.passphrase!==undefined)$(role+'LocalPassphrase').value=values.passphrase;
  $(role+'Host').dataset.sshAlias=values.alias||'';
  const alias=document.querySelector('[data-alias-scope=install][data-alias-role='+role+']');if(alias)alias.value=values.alias||'';
 }
 if(changed){for(const role of ['ru','nl']){$(role+'Method').onchange();clearCommand(role);}$('confirmation').checked=false;scheduleSession();if(page===3)review();}
});
window.addEventListener('vpnai-open-installation',()=>show(page<1?1:page));
window.vpnaiServerFiles.adapters.push({
 canImport:()=>sessionReady&&!terminated&&!running&&!backupsLoading&&!currentConfigLoading,
 apply:servers=>{
  for(const role of ['ru','nl']){
   const values=servers[role];$(role+'Host').dataset.sshAlias='';
   const alias=document.querySelector('[data-alias-scope=install][data-alias-role='+role+']');if(alias)alias.value='';
   for(const [key,suffix] of Object.entries({host:'Host',port:'Port',user:'User',method:'Method',password:'Password',key:'Key',key_path:'KeyPath',passphrase:'Passphrase'}))$(role+suffix).value=values[key];
   $(role+'LocalPassphrase').value='';$(role+'Method').onchange();clearCommand(role);
  }
  $('confirmation').checked=false;scheduleSession();if(page===3)review();
 }
});

function clearCommand(role){for(const suffix of ['CopyCommand','CopyButton','Fallback'])$(role+suffix).classList.add('hidden');$(role+'CopyButton').textContent='Скопировать команду';}
async function makeCommand(role){
 message('');const button=$(role+'MakeCommand');button.disabled=true;
 try{const result=await api('/api/ssh-command',{host:$(role+'Host').value,alias:$(role+'Host').dataset.sshAlias||'',port:$(role+'Port').value,platform:$(role+'CommandOS').value,key_path:$(role+'KeyPath').value});$(role+'CopyCommand').textContent=result.command;$(role+'CopyCommand').classList.remove('hidden');$(role+'CopyButton').classList.remove('hidden');$(role+'CopyButton').textContent='Скопировать команду';$(role+'FallbackCommand').textContent=result.fallback;$(role+'Fallback').classList.toggle('hidden',!result.fallback);}
 catch(e){message(e.message);}finally{button.disabled=false;}
}
async function copyCommand(role,fallback){
 try{await navigator.clipboard.writeText($(role+(fallback?'FallbackCommand':'CopyCommand')).textContent);$(role+(fallback?'FallbackCopy':'CopyButton')).textContent='Скопировано ✓';}
 catch(e){message('Не удалось записать в буфер. Выделите команду и скопируйте вручную.');}
}


(()=>{'use strict';
const el=id=>document.getElementById(id),esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let section='overview',routeTab='iplist',mode='connection';
let users=[],lists={ru:[],eu:[],iplist:[]},snapshot={connected:false,servers:{},sessions:[],warnings:[]},busy=false;
let connectionDraft={ru:{host:'',port:22,user:'root',method:'password',password:'',key:'',key_path:'~/.ssh/id_ed25519',passphrase:''},nl:{host:'',port:22,user:'root',method:'password',password:'',key:'',key_path:'~/.ssh/id_ed25519',passphrase:''},eu_ssh:'direct',eu_target:'public'};
let connectionReady=false,draftRevision=0,draftTimer=null;
const csrf=()=>sessionStorage.getItem('vpn-local-token')||'';
async function request(action,data={}){const response=await fetch('/api/admin/'+action,{method:'POST',headers:{'Content-Type':'application/json','X-Local-Token':csrf()},body:JSON.stringify(data)});if(!response.ok){const error=await response.json();throw Error(error.error||'Ошибка запроса.');}return action==='profiles'?response.blob():response.json();}
window.vpnaiServerFiles.adapters.push({
 canImport:()=>connectionReady&&!busy,
 apply:servers=>{for(const role of ['ru','nl'])connectionDraft[role]={...servers[role]};scheduleConnectionSave();render();}
});


let initialSharedDraft=false;
function publishSharedDraft(){window.vpnaiUnified.eu_ssh=connectionDraft.eu_ssh||'direct';window.vpnaiUnified.eu_target=connectionDraft.eu_target||'public';window.dispatchEvent(new CustomEvent('vpnai-shared-servers',{detail:JSON.parse(JSON.stringify(connectionDraft))}));}
function hydrateSharedDraft(){
 if(!connectionReady||!window.vpnaiUnified.installerReady)return;
 if(!initialSharedDraft){
  if(!['ru','nl'].some(role=>connectionDraft[role].host))for(const role of ['ru','nl'])Object.assign(connectionDraft[role],window.vpnaiUnified.installDraft?.[role]||{});
  initialSharedDraft=true;
 }
 publishSharedDraft();render();
}
window.addEventListener('vpnai-install-draft-ready',hydrateSharedDraft);
window.addEventListener('vpnai-open-connection',()=>setMode('connection'));
function connectionHint(){return '<div class="workflow-connection-hint"><div><strong>Сначала подключите серверы</strong><p>Укажите SSH-доступ к RU и EU в общем разделе «Подключение».</p></div><button type="button" class="secondary" data-open-shared-connection>Подключение </button></div>';}
function scheduleConnectionSave(){if(!connectionReady)return;publishSharedDraft();clearTimeout(draftTimer);draftTimer=setTimeout(()=>saveConnectionDraft().catch(e=>toast('Данные сеанса не сохранены: '+e.message)),200);}
async function saveConnectionDraft(keepalive=false){clearTimeout(draftTimer);if(!connectionReady)return;publishSharedDraft();draftRevision=Math.max(Date.now(),draftRevision+1);const payload={draft:JSON.parse(JSON.stringify(connectionDraft)),revision:draftRevision};if(keepalive){fetch('/api/admin/save-connection-session',{method:'POST',headers:{'Content-Type':'application/json','X-Local-Token':csrf()},body:JSON.stringify(payload),keepalive:true}).catch(()=>{});return;}return request('save-connection-session',payload);}
function bytes(n){if(n===undefined||n===null)return '—';let unit=0;const units=['Б','КиБ','МиБ','ГиБ','ТиБ'];while(n>=1024&&unit<4){n/=1024;unit++;}return (unit?n.toFixed(2):n)+' '+units[unit];}
function duration(n){if(n===null||n===undefined)return '—';n=Math.max(0,Math.floor(n));return n>=86400?Math.floor(n/86400)+' дн. '+Math.floor(n%86400/3600)+' ч.':n>=3600?Math.floor(n/3600)+' ч. '+Math.floor(n%3600/60)+' мин':Math.floor(n/60)+' мин';}
function acceptSnapshot(data){snapshot=data;users=(data.users||[]).map(u=>{const sessions=(data.sessions||[]).filter(s=>s.name===u.name);return {...u,sessions,online:sessions.length>0,clientIp:sessions.map(s=>s.client_ip).join(', '),ip:sessions.map(s=>s.vpn_ip).join(', ')||'—',since:sessions.map(s=>duration(s.since?Date.now()/1000-s.since:null)).join(', '),traffic:bytes(sessions.reduce((total,s)=>total+s.bytes_received+s.bytes_sent,0)),sessionCount:sessions.length};});updateIndicators();}
function updateIndicators(){for(const id of ['modeAdmin']){el(id).classList.toggle('server-connected',snapshot.connected===true);el(id).querySelector('.mode-connection-dot').setAttribute('aria-label',snapshot.connected?'Соединение с серверами проверено':'Нет подтверждённого соединения');}syncWorkspaceConnectionBadge();}
let managementRead=null;
function loadManagementData(){
 if(managementRead)return managementRead;
 if(busy)return Promise.resolve();
 busy=true;window.vpnaiDNSPreview.setReading(true);
 managementRead=(async()=>{
  try{
   await refresh();
   if(snapshot.connected){
    await window.vpnaiLimits.read();
    try{window.vpnaiDNSPreview.syncFromServer(await request('dns-status'),true);}
    catch(error){window.vpnaiDNSPreview.syncFromServer(null,true,error.message);toast('Данные управления прочитаны, но DNS не считан: '+error.message);}
   }else window.vpnaiDNSPreview.syncFromServer(null,true,'Нет подтверждённого подключения к обоим серверам');
  }catch(error){snapshot.connected=false;updateIndicators();toast('Не удалось обновить данные с серверов: '+error.message);}
  finally{busy=false;managementRead=null;window.vpnaiDNSPreview.setReading(false);if(mode==='admin')render();}
 })();
 return managementRead;
}
async function refresh(){acceptSnapshot(await request('status'));if(snapshot.connected)lists=await request('routes');render();}
async function operation(action,data={},reload=true){if(busy)return;busy=true;document.querySelectorAll('.admin-modal button').forEach(b=>b.disabled=true);try{const answer=await request(action,data);if(reload){try{await refresh();}catch(e){snapshot.connected=false;updateIndicators();toast('Операция выполнена, но данные не обновились: '+e.message);}}return answer;}finally{busy=false;document.querySelectorAll('.admin-modal button').forEach(b=>b.disabled=false);}}
const pages={overview:['01','Управление'],profiles:['02','Конфигурации'],routes:['03','Маршрутизация']};
const button=(text,action,primary=false)=>`<button class="${primary?'primary':'secondary'}" data-admin-action="${action}">${text}</button>`;
const note='<div class="demo-note"><span>◇</span> Данные доступа хранятся только в памяти текущего запуска приложения.</div>';
function toast(text){document.querySelector('.toast')?.remove();const d=document.createElement('div');d.className='toast';d.setAttribute('role','status');d.textContent=text;document.body.append(d);setTimeout(()=>d.remove(),4500);}
function nav(){el('adminNav').innerHTML='<div class="admin-caption">УПРАВЛЕНИЕ</div>'+Object.entries(pages).map(([k,[icon,title]])=>`<button class="admin-nav ${k===section?'active':''}" data-admin-page="${k}"><span aria-hidden="true">${icon}</span>${title}</button>`).join('');}
function heading(title,desc,action=''){return `<div class="admin-page-intro"><div class="step-heading"><div class="eyebrow">${mode==='connection'?'ПОДКЛЮЧЕНИЕ':'УПРАВЛЕНИЕ'}</div><nav class="help-menu" aria-label="Документация"><details class="connection-file-menu"><summary>Файл</summary><div class="connection-file-popup"><button type="button" data-server-file-download>Скачать файл</button><button type="button" data-server-file-upload>Загрузить файл</button><p>Шаблон JSON для RU и EU. Можно загрузить .json или .txt с такой же структурой. Заполненный файл содержит пароли.</p></div></details><a href="/help" target="_blank" rel="noopener">Инструкция</a><a href="/docs/SETUP.md" target="_blank" rel="noopener">Настройка</a></nav></div><div class="admin-heading page-intro"><div class="intro-copy"><h1>${title}</h1><p class="lead">${desc}</p></div>${action}</div></div>`;}
function card(title,body,action=''){return `<div class="admin-card"><div class="admin-card-head"><h2>${title}</h2>${action}</div>${body}</div>`;}
function status(on){return `<span class="status ${on?'':'off'}">${on?'Подключён':'Не в сети'}</span>`;}
function userRows(rows,actions=true){
 const header=`<thead><tr><th>ПОЛЬЗОВАТЕЛЬ</th><th>ПОДКЛЮЧЕНИЕ</th><th>IP КЛИЕНТА</th><th>VPN-АДРЕС</th><th>В СЕТИ</th><th>ТРАФИК ↓↑</th>${actions?'<th>УПРАВЛЯТЬ</th>':''}</tr></thead>`;
 const body=rows.map(u=>{const sessions=u.sessions?.length?u.sessions:[null],count=sessions.length;return sessions.map((session,index)=>`<tr class="${index===0?'user-session-start':'user-session-continuation'}">${index===0?`<td rowspan="${count}" class="user-identity-cell"><div class="user-cell"><span class="avatar user-limit-badge" aria-label="Максимальное количество подключений: ${window.vpnaiLimits.label(u.name)}"><strong>${window.vpnaiLimits.label(u.name)}</strong><small>max</small></span><div>${esc(u.name)}<small>${esc(u.comment)}</small></div></div></td><td rowspan="${count}" class="user-state-cell">${snapshot.sessions_available===false?'<span class="muted">Неизвестно</span>':status(u.online)}${u.sessionCount>1?`<small>${u.sessionCount} подключения</small>`:''}</td>`:''}<td class="muted">${session?esc(session.client_ip||'—'):'—'}</td><td class="muted">${session?esc(session.vpn_ip||'—'):'—'}</td><td>${session?esc(duration(session.since?Date.now()/1000-session.since:null)):'—'}</td><td>${snapshot.sessions_available===false?'—':session?esc(bytes(session.bytes_received+session.bytes_sent)):'0 Б'}</td>${index===0&&actions?`<td rowspan="${count}" class="user-actions-cell"><div class="user-action-anchor"><button class="admin-link" data-user="${esc(u.name)}">Управлять </button></div></td>`:''}</tr>`).join('');}).join('')||`<tr><td colspan="${actions?7:6}">Ничего не найдено</td></tr>`;
 return `<div class="table-wrap"><table class="admin-table users-table">${header}<tbody>${body}</tbody></table></div>`;
}

function server(role,title){const item=snapshot.servers[role]||{};const path=role==='nl'&&snapshot.eu_ssh==='via_ru'?`<span class="eu-path-pill">через RU${snapshot.eu_target==='gre'?' · GRE':''}</span>`:role==='nl'?`<span class="eu-path-pill muted">напрямую</span>`:'';return `<div class="admin-card"><div class="admin-card-body"><div class="admin-server"><span class="server-icon">${role==='ru'?'RU':'EU'}</span><div><h2>${title}</h2><p>${esc(item.host||'Не подключён')} · ${esc(item.os||'—')}</p>${path}</div><span class="status ${item.available?'':'off'}">${item.available?'Доступен':'Нет связи'}</span></div><div class="server-stats"><div><small>Загрузка CPU</small><strong>${item.cpu===undefined?'—':item.cpu+'%'}</strong></div><div><small>Память</small><strong>${item.memory_used==null||item.memory_total==null?'—':Number((item.memory_used/1000000000).toFixed(2))+'/'+Number((item.memory_total/1000000000).toFixed(2))+' GB'}</strong></div><div><small>Время работы</small><strong>${duration(item.uptime)}</strong></div></div></div></div>`;}

function userTableActions(){return `<div class="user-table-actions"><span class="muted small">Всего: ${users.length}</span>${button('＋ Пользователь','add-user',true)}</div>`;}
function tunnelInfo(){const t=snapshot.tunnel||{},up=t.state==='up',down=t.state==='down';return `<div class="tunnel-status ${up?'is-up':down?'is-down':'is-unknown'}" title="${esc(t.detail||'Подключитесь к серверам для проверки туннеля.')}"><span class="tunnel-status-copy"><strong>GRE / IPsec</strong><small>${up?'Туннель работает':down?'Туннель недоступен':'Не проверен'}</small></span><span class="tunnel-status-reading"><span class="tunnel-status-dot" aria-hidden="true"></span><span class="tunnel-latency">${t.latency_ms!==null&&t.latency_ms!==undefined?esc(t.latency_ms)+' мс':'— мс'}</span></span></div>`;}

function overview(){const sessions=snapshot.sessions||[];return heading('Ваш VPN под контролем.','Серверы, подключения и доступ — в одном месте.')+`<div class="overview-layout"><div class="admin-button-row overview-refresh">${button('↻ Обновить','refresh')}</div><div class="metric-grid">${[[snapshot.sessions_available===false?'—':sessions.length,'Активных подключений','UDP и TCP'],[users.length,'Пользователи','Индивидуальные профили'],[bytes(sessions.reduce((n,s)=>n+s.bytes_received+s.bytes_sent,0)),'Трафик текущих сессий','Принято и отправлено'],[Object.values(snapshot.servers).filter(s=>s.available).length+' / 2','Серверы доступны','Россия → Европа']].map(([v,k,d])=>`<div class="metric"><small>${k}</small><strong>${v}</strong><p>${d}</p></div>`).join('')}</div><div class="admin-grid">${server('ru','Российский сервер')}${server('nl','Зарубежный сервер')}</div>${snapshot.warnings?.length?`<div class="notice">${snapshot.warnings.map(esc).join('<br>')}</div>`:''}<div class="toolbar"><input id="userSearch" aria-label="Поиск пользователей" placeholder="Поиск по имени или комментарию">${tunnelInfo()}</div><div id="userTable">${card('Пользователи и подключения',userRows(users),userTableActions())}</div><div class="quick-actions"><button data-admin-page="profiles">Скачать конфигурации<small>Профили UDP / TCP и данные входа</small></button><button data-admin-page="routes">⌘ Настроить маршруты<small>IPList, ручные списки RU-EU и RU</small></button><button data-admin-page="connection">⚙ Подключение<small>Данные серверов и SSH-доступ</small></button></div></div>`;}

function profilesPage(){return heading('Конфигурации','Подготовьте файлы для OpenVPN Connect и других клиентов.',button('↓ Все конфигурации','all-profiles',true))+card('Профили пользователей',`<div class="table-wrap"><table class="admin-table profiles-table"><thead><tr><th>ПОЛЬЗОВАТЕЛЬ</th><th>ПРОФИЛИ</th><th>АВТОРИЗАЦИЯ</th><th></th></tr></thead><tbody>${users.map(u=>`<tr><td>${esc(u.name)}<small>${esc(u.comment)}</small></td><td><span class="protocol">UDP</span> <span class="protocol">TCP</span></td><td class="muted">Из профиля OpenVPN</td><td><button class="admin-link" data-profile="${esc(u.name)}">Получить файлы </button></td></tr>`).join('')}</tbody></table></div>`)+`<div class="notice">Архив будет включать профили .ovpn и данные входа. Для передачи на другое устройство можно будет создать временную ссылку на 10 минут.</div>`;}
function routesPage(){const names={iplist:'RU-EU IPList',eu:'RU-EU',ru:'RU'},descs={iplist:'Автоматический список адресов, которые выходят через зарубежный сервер.',eu:'Ручные адреса через зарубежный сервер. Дополняют автоматический IPList.',ru:'Ручные адреса через российский сервер. Имеют приоритет над RU-EU и IPList.'};return heading('Маршрутизация','Управляйте тем, через какой сервер проходит трафик.')+window.vpnaiLimits.panel('management')+window.vpnaiDNSPreview.panel('management',snapshot.connected)+`<div class="tunnel"><span>Текущий режим</span><strong>${esc(({split:'Раздельные маршруты',full_mixed:'Весь IPv4 через VPN',full_nl:'Весь IPv4 через зарубежный сервер'})[snapshot.routing]||'Не определён')}</strong><span>RU имеет приоритет</span></div><div class="admin-tabs">${Object.entries(names).map(([k,n])=>`<button data-route-tab="${k}" class="${routeTab===k?'active':''}">${n} <small> ${lists[k].length}</small></button>`).join('')}</div>`+card(names[routeTab],`<div class="route-info"><h2>${routeTab==='ru'?'Выход через Россию':'Выход через Европу'}</h2>${descs[routeTab]}<p class="small">Данные получены с российского сервера.</p></div>${lists[routeTab].map((ip,i)=>`<div class="route-entry"><span>${ip}</span>${routeTab==='iplist'?'<span class="muted small">IPList</span>':`<button class="admin-link danger-text" data-remove-route="${i}">Удалить</button>`}</div>`).join('')||'<div class="empty-demo">В списке пока нет адресов.</div>'}`,button(routeTab==='iplist'?'↻ Обновить с сайта':'＋ Добавить IP',routeTab==='iplist'?'update-iplist':'add-route'))+`<div class="notice">После изменения маршрутов устройства нужно будет переподключить к VPN. Остальные списки сохраняются.</div>`;}
function connectionPage(){return heading('Подключение','Подключитесь к серверам, затем выберите установку или управление.')+`<div class="admin-grid">${['ru','nl'].map(role=>{const d=connectionDraft[role];return card(role==='ru'?'Российский сервер':'Зарубежный сервер',`<div class="admin-card-body"><div class="fields"><label>IP-адрес<div class="host-picker"><input data-connection-role="${role}" data-field="host" value="${esc(d.host)}" placeholder="Публичный IPv4 или выберите алиас" autocomplete="off">${sshAliasSelect('admin',role,d.alias||'')}</div></label><div class="fields two"><label>SSH-порт<input data-connection-role="${role}" data-field="port" value="${esc(d.port)}" type="number" min="1" max="65535"></label><label>Пользователь<input value="root" readonly></label></div><label>Способ подключения<select data-connection-role="${role}" data-field="method">${[['password','Пароль'],['key','Приватный SSH-ключ'],['local-key','Локальный SSH-ключ']].map(([k,v])=>`<option value="${k}" ${d.method===k?'selected':''}>${v}</option>`).join('')}</select></label>${d.method==='password'?`<label>Пароль SSH<input data-connection-role="${role}" data-field="password" type="password" value="${esc(d.password)}" autocomplete="off"></label>`:d.method==='key'?`<label>Приватный SSH-ключ<textarea data-connection-role="${role}" data-field="key" autocomplete="off">${esc(d.key)}</textarea></label>`:`<label>Путь к приватному ключу<input data-connection-role="${role}" data-field="key_path" value="${esc(d.key_path)}"></label>`}${d.method!=='password'?`<label>Пароль ключа<input data-connection-role="${role}" data-field="passphrase" type="password" value="${esc(d.passphrase)}" autocomplete="off"></label>`:''}</div></div>`);}).join('')}</div><section class="admin-card eu-ssh-card"><div class="admin-card-head"><h2>SSH к зарубежному серверу</h2></div><div class="admin-card-body"><p class="eu-ssh-lead">Если публичный SSH к EU закрыт, команды пойдут через российский сервер.</p><div class="eu-ssh-seg" role="group" aria-label="Путь SSH к EU"><button type="button" class="eu-ssh-option ${connectionDraft.eu_ssh!=='via_ru'?'active':''}" data-eu-ssh="direct">Напрямую</button><button type="button" class="eu-ssh-option ${connectionDraft.eu_ssh==='via_ru'?'active':''}" data-eu-ssh="via_ru">Через RU</button></div>${connectionDraft.eu_ssh==='via_ru'?`<div class="eu-ssh-seg eu-target-seg" role="group" aria-label="Цель на EU"><button type="button" class="eu-ssh-option ${connectionDraft.eu_target!=='gre'?'active':''}" data-eu-target="public">Публичный IP EU</button><button type="button" class="eu-ssh-option ${connectionDraft.eu_target==='gre'?'active':''}" data-eu-target="gre">GRE 10.78.0.2</button></div><p class="hint">С RU должен быть доступен SSH EU. GRE — после установки, когда туннель уже работает. Отпечаток EU подтверждается как обычно.</p>`:`<p class="hint">Прямое SSH-подключение с этого устройства к публичному IP EU.</p>`}</div></section><div class="admin-button-row web-connection-actions">${button('Отключиться','disconnect')}${button('Подключиться','connect',true)}</div><div class="notice">При первом подключении сверьте и подтвердите SSH-отпечатки. Управление использует команды уже установленного VPNAI. Изменения применяются к реальным серверам.${connectionDraft.eu_ssh==='via_ru'?' В режиме «Через RU» отпечаток EU читается через российский сервер.':''}</div><div class="workflow-next"><h2>Что дальше?</h2><p>Подключение общее для установки и управления.</p><div><button class="secondary" type="button" data-next-workspace="install" ${snapshot.connected?'':'disabled'}>Установка </button><button class="primary" type="button" data-next-workspace="admin" ${snapshot.connected?'':'disabled'}>Управление </button></div></div>`;}

function render(){document.body.dataset.workspaceSection=mode==='connection'?'connection':section;nav();el('adminView').innerHTML=(mode==='connection'?connectionPage():((!snapshot.connected?connectionHint():'')+({overview,profiles:profilesPage,routes:routesPage}[section]||overview)()))+note;if(!connectionReady&&mode==='connection')el('adminView').querySelectorAll('input,select,[data-admin-action=connect]').forEach(n=>n.disabled=true);const search=el('userSearch');if(search)search.oninput=()=>{const q=search.value.toLowerCase();el('userTable').innerHTML=card('Пользователи и подключения',userRows(users.filter(u=>(u.name+' '+u.comment).toLowerCase().includes(q))),userTableActions());};}
function setMode(m){
 mode=m;document.body.dataset.workspaceMode=m;el('connectionNav').classList.toggle('hidden',m!=='connection');
 el('installView').classList.toggle('hidden',m!=='install');el('installNav').classList.toggle('hidden',m!=='install');
 el('adminView').classList.toggle('hidden',m==='install');el('adminNav').classList.toggle('hidden',m!=='admin');
 for(const [id,value] of [['modeConnection','connection'],['modeInstall','install'],['modeAdmin','admin']]){el(id).classList.toggle('selected',m===value);el(id).setAttribute('aria-pressed',m===value?'true':'false');}
 if(m==='install'){el('installConnectionHint').innerHTML=!snapshot.connected?connectionHint():'';window.dispatchEvent(new Event('vpnai-open-installation'));}else render();
 syncWorkspaceConnectionBadge();if(m==='admin')loadManagementData();window.scrollTo(0,0);
}

function modal(title,body,submit,onSubmit){document.querySelector('.admin-modal')?.remove();const d=document.createElement('div');d.className='admin-modal';d.innerHTML=`<form class="modal-box" role="dialog" aria-modal="true" aria-labelledby="dialogTitle"><span class="demo-label">Управление сервером</span><h2 id="dialogTitle">${title}</h2>${body}<div class="error hidden" role="alert"></div><div class="modal-actions"><button type="button" class="secondary" data-close-modal>Закрыть</button>${submit?`<button type="submit" class="primary">${submit}</button>`:''}</div></form>`;document.body.append(d);d.querySelector('[data-close-modal]').onclick=()=>{if(!busy)d.remove();};d.onclick=e=>{if(e.target===d&&!busy)d.remove();};d.querySelector('form').onsubmit=async e=>{e.preventDefault();if(busy)return;const error=d.querySelector('.error');error.classList.add('hidden');try{if(await onSubmit?.(d)!==false)d.remove();}catch(e){error.textContent=e.message;error.classList.remove('hidden');}};d.querySelector('input,button')?.focus();return d;}

function generatedPassword(){const alphabet='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%';const values=new Uint32Array(18);crypto.getRandomValues(values);return Array.from(values,n=>alphabet[n%alphabet.length]).join('');}
async function editCredentials(name){const user=users.find(u=>u.name===name);if(!user)return;const saved=await request('credentials',{name});
const d=modal('Пароль и комментарий',`<p>Пользователь <strong>${esc(name)}</strong></p><label>Комментарий<input id="editUserComment" maxlength="200" value="${esc(user.comment)}"></label><label>Пароль<div class="password-field"><input id="editUserPassword" type="password" maxlength="256" autocomplete="new-password" placeholder="Не менять пароль"><button class="admin-link" type="button" id="toggleUserPassword">Показать</button></div></label><div class="credential-actions"><button type="button" class="secondary" id="generateUserPassword">Сгенерировать пароль</button></div><p>Пустое поле сохраняет текущий пароль. Новый пароль применяется после сохранения. Активные устройства потребуется переподключить.</p>`,'Сохранить на сервере',async d=>{const password=d.querySelector('#editUserPassword').value;await operation('update',{name,comment:d.querySelector('#editUserComment').value,password:password===saved.password?'':password});toast('Изменения сохранены на сервере.');});
const input=d.querySelector('#editUserPassword');
d.querySelector('#toggleUserPassword').onclick=e=>{if(!input.value&&saved.password){input.value=saved.password;}const show=input.type==='password';input.type=show?'text':'password';e.target.textContent=show?'Скрыть':'Показать';};
d.querySelector('#generateUserPassword').onclick=()=>{input.value=generatedPassword();input.type='text';d.querySelector('#toggleUserPassword').textContent='Скрыть';};
}


function profiles(name){if(!name){modal('Все конфигурации',`<p>Архив с профилями всех пользователей.</p><div class="choice-stack"><button type="button" class="choice profile-delivery-choice" data-export-name=""><span><strong>Скачать ZIP-архив</strong><small>Скачать конфигурацию на устройство</small></span><span class="user-menu-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 3v12 M7 10l5 5 5-5 M4 16v5h16v-5"/></svg></span></button><button type="button" class="choice" data-link-name="">Создать ссылку на 10 минут</button></div>`);return;}modal('Конфигурации · '+esc(name||'все пользователи'),`<p>Профили OpenVPN для UDP и TCP.</p><div class="choice-stack"><button type="button" class="choice profile-delivery-choice" data-config-share="${esc(name||'')}"><span><strong>QR-код и ссылка</strong><small>Скачать конфигурацию на другое устройство</small></span><span class="user-menu-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M3 3h6v6H3z M15 3h6v6h-6z M3 15h6v6H3z M15 15h3v3h3v3h-6z"/></svg></span></button><button type="button" class="choice profile-delivery-choice" data-export-name="${esc(name||'')}"><span><strong>Скачать ZIP-архив</strong><small>Скачать конфигурацию на устройство</small></span><span class="user-menu-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 3v12 M7 10l5 5 5-5 M4 16v5h16v-5"/></svg></span></button></div>`);}
function configurationShare(name){
 const d=modal('QR-код и ссылка',`<p>Пользователь <strong>${esc(name)}</strong></p><div class="config-protocols" aria-label="Протокол конфигурации"><button type="button" class="secondary active" data-share-protocol="udp" aria-pressed="true">UDP</button><button type="button" class="secondary" data-share-protocol="tcp" aria-pressed="false">TCP</button></div><section class="config-share-block"><h3>QR-код</h3><p>Отсканируйте, чтобы скачать файл конфигурации.</p><div class="config-download-qr"></div><span class="config-file-name"></span></section><section class="config-share-block"><h3>Ссылка</h3><p>Скачивает тот же файл, что и QR-код.</p><label class="visually-hidden" for="configurationDownloadLink">Ссылка на конфигурацию</label><input id="configurationDownloadLink" readonly><div class="config-link-actions"><button type="button" class="secondary" data-copy-config-link disabled>Скопировать ссылку</button><a class="primary" data-open-config-link download>Скачать файл</a></div></section><p data-share-status role="status">Создаём ссылку…</p><button type="button" class="secondary hidden" data-renew-config-link>Создать новую ссылку</button><p class="muted small">Ссылка и QR-код действуют 10 минут с момента создания. Передавайте их только владельцу доступа.</p>`);
 let generation=0,selectedProtocol='udp',timer;
 const load=async protocol=>{const ticket=++generation;selectedProtocol=protocol;clearInterval(timer);d.querySelector('[data-share-status]').textContent='Получаем ссылку…';d.querySelector('.config-download-qr').replaceChildren();d.querySelector('#configurationDownloadLink').value='';d.querySelector('[data-open-config-link]').removeAttribute('href');d.querySelector('[data-copy-config-link]').disabled=true;d.querySelector('[data-renew-config-link]').classList.add('hidden');
 d.querySelectorAll('[data-share-protocol]').forEach(b=>{b.classList.toggle('active',b.dataset.shareProtocol===protocol);b.setAttribute('aria-pressed',String(b.dataset.shareProtocol===protocol));});
 try{const result=await operation('profile-link',{name,protocol},false);if(!d.isConnected||ticket!==generation)return;const url=new URL(result.url);if(url.protocol!=='https:')throw Error('Сервер вернул ссылку без HTTPS.');const qr=qrcode(0,'M');qr.addData(url.href,'Byte');qr.make();d.querySelector('.config-download-qr').innerHTML=qr.createSvgTag({cellSize:6,margin:16,scalable:true});d.querySelector('.config-file-name').textContent=result.filename;d.querySelector('#configurationDownloadLink').value=url.href;const link=d.querySelector('[data-open-config-link]');link.href=url.href;link.download=result.filename;d.querySelector('[data-copy-config-link]').disabled=false;
 const deadline=Date.now()+Math.max(0,Math.min(600,result.expires-(result.server_time||Date.now()/1000)))*1000;
 const tick=()=>{if(!d.isConnected){clearInterval(timer);return;}const left=Math.max(0,Math.ceil((deadline-Date.now())/1000));d.querySelector('[data-share-status]').textContent=left?'Ссылка и QR-код действуют ещё '+Math.floor(left/60)+':'+String(left%60).padStart(2,'0'):'Срок ссылки и QR-кода истёк.';if(!left){clearInterval(timer);d.querySelector('.config-download-qr').replaceChildren();link.removeAttribute('href');d.querySelector('[data-copy-config-link]').disabled=true;d.querySelector('[data-renew-config-link]').classList.remove('hidden');}};tick();timer=setInterval(tick,1000);
 }catch(error){if(d.isConnected){d.querySelector('[data-copy-config-link]').disabled=true;d.querySelector('[data-open-config-link]').removeAttribute('href');d.querySelector('[data-share-status]').textContent=error.message;d.querySelector('[data-renew-config-link]').classList.remove('hidden');}}};
 d.querySelectorAll('[data-share-protocol]').forEach(b=>b.onclick=()=>load(b.dataset.shareProtocol));d.querySelector('[data-renew-config-link]').onclick=()=>load(selectedProtocol);d.querySelector('[data-copy-config-link]').onclick=async()=>{try{await navigator.clipboard.writeText(d.querySelector('#configurationDownloadLink').value);toast('Ссылка скопирована.');}catch{d.querySelector('#configurationDownloadLink').select();toast('Выделена ссылка — скопируйте её.');}};load('udp');
}

function requireConnection(){if(!snapshot.connected){setMode('connection');toast('Сначала подключитесь к серверам.');return false;}return true;}
async function connect(){window.vpnaiLimits.reset();await saveConnectionDraft();const settings=JSON.parse(JSON.stringify(connectionDraft));settings.action='check';const trust=await api('/api/ssh/prepare',settings);if(trust.confirmation_required){if(!window.confirm('Сверьте SSH-отпечатки серверов:\n'+trust.servers.map(s=>s.host+'\n'+s.fingerprint).join('\n\n')+'\n\nДоверять этим ключам?'))return;await api('/api/ssh/confirm',{accept:true,confirmation_token:trust.confirmation_token});}acceptSnapshot(await request('connect',settings));lists=await request('routes');section='overview';setMode('connection');window.vpnaiConnectionNotice('Подключено');}
document.addEventListener('input',e=>{const t=e.target;if(t.dataset.connectionRole){const role=t.dataset.connectionRole;connectionDraft[role][t.dataset.field]=t.dataset.field==='port'?Number(t.value):t.value;if(t.dataset.field==='host'){connectionDraft[role].alias='';const menu=t.parentElement.querySelector('select');if(menu)menu.value='';}scheduleConnectionSave();}});
document.addEventListener('change',async e=>{const t=e.target;
if(t.dataset.aliasScope){try{if(!t.value)return;const chosen=t.value,role=t.dataset.aliasRole;const entry=await api('/api/ssh/alias',{alias:chosen});
if(t.dataset.aliasScope==='admin'){connectionDraft[role]={...connectionDraft[role],host:entry.host,port:entry.port,user:entry.user,method:entry.method,key_path:entry.key_path||'~/.ssh/id_ed25519',alias:entry.alias,password:'',key:'',passphrase:''};await saveConnectionDraft();render();}
else{const host=document.getElementById(role+'Host');host.value=entry.host;host.dataset.sshAlias=entry.alias;document.getElementById(role+'Port').value=entry.port;document.getElementById(role+'User').value=entry.user;document.getElementById(role+'Method').value=entry.method;if(entry.key_path)document.getElementById(role+'KeyPath').value=entry.key_path;for(const suffix of ['Password','Key','Passphrase','LocalPassphrase'])document.getElementById(role+suffix).value='';document.getElementById(role+'Method').onchange();invalidatePins();clearCommand(role);scheduleSession();}
}catch(error){t.value='';toast(error.message);}return;}
if(t.dataset.connectionRole){if(t.dataset.field==='method'){connectionDraft[t.dataset.connectionRole].method=t.value;render();}try{await saveConnectionDraft();}catch(error){toast(error.message);}}
});
window.addEventListener('pagehide',()=>saveConnectionDraft(true));
document.addEventListener('click',async e=>{const target=e.target.closest('button');if(!target||busy)return;try{
if(target.hasAttribute('data-save-limit-default')){if(await window.vpnaiLimits.saveDefault(target.closest('.connection-limit-panel').querySelector('select').value)){render();toast('Лимит по умолчанию сохранён на сервере.');}return;}
if(target.hasAttribute('data-eu-ssh')){connectionDraft.eu_ssh=target.getAttribute('data-eu-ssh');if(connectionDraft.eu_ssh!=='via_ru')connectionDraft.eu_target='public';scheduleConnectionSave();render();return;}if(target.hasAttribute('data-eu-target')){connectionDraft.eu_target=target.getAttribute('data-eu-target');scheduleConnectionSave();render();return;}if(target.hasAttribute('data-open-shared-connection')){setMode('connection');return;}if(target.dataset.nextWorkspace){setMode(target.dataset.nextWorkspace);return;}
if(target.dataset.adminPage==='connection'){setMode('connection');return;}
if(target.dataset.adminPage){section=target.dataset.adminPage;render();loadManagementData();window.scrollTo(0,0);return;}
if(target.dataset.routeTab){routeTab=target.dataset.routeTab;render();return;}
const a=target.dataset.adminAction;
if(a==='connect'){busy=true;try{await connect();}catch(error){window.vpnaiConnectionNotice(error.message,true);}finally{busy=false;}return;}
if(a==='disconnect'){await operation('disconnect',{},false);window.vpnaiLimits.reset();acceptSnapshot({connected:false,servers:{},users:[],sessions:[],warnings:[]});lists={ru:[],eu:[],iplist:[]};section='overview';setMode('connection');return;}
if(!target.closest('#adminView,.admin-modal'))return;
if(!requireConnection())return;
if(a==='refresh'){await loadManagementData();return;}
if(target.hasAttribute('data-config-share')){configurationShare(target.dataset.configShare);return;}
if(target.dataset.user){const name=target.dataset.user;modal(esc(name),`<p>Управление доступом пользователя.</p><div class="choice-stack user-menu-actions"><button type="button" class="choice" data-profile="${esc(name)}">Конфигурации UDP / TCP<span class="user-menu-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M6 3h8l4 4v14H6z M14 3v5h4 M9 12h6 M9 16h6"/></svg></span></button><button type="button" class="choice" data-password="${esc(name)}">Пароль и комментарий<span class="user-menu-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="8" cy="9" r="4"/><path d="m11 12 8 8 M15 16l3-3 M17 18l3-3"/></svg></span></button><button type="button" class="choice" data-user-limit="${esc(name)}">Одновременные подключения <span class="avatar user-limit-badge" aria-label="Максимальное количество подключений: ${window.vpnaiLimits.label(name)}"><strong>${window.vpnaiLimits.label(name)}</strong><small>max</small></span></button><button type="button" class="choice danger-text" data-delete-user="${esc(name)}">Удалить пользователя<span class="user-menu-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 7h16 M9 7V4h6v3 M6 7l1 14h10l1-14 M10 11v6 M14 11v6"/></svg></span></button></div>`);}
if(target.dataset.userLimit){const name=target.dataset.userLimit;await window.vpnaiLimits.read();modal('Одновременные подключения',window.vpnaiLimits.userPanel(name),'Сохранить',async d=>{if(!await window.vpnaiLimits.saveUser(name,d.querySelector('[data-user-limit-value]').value,d.querySelector('[data-limit-revision]').value))return false;render();toast('Лимит пользователя сохранён на сервере.');});return;}
if(target.dataset.password)await editCredentials(target.dataset.password);
if(target.dataset.profile)profiles(target.dataset.profile);
if(target.hasAttribute('data-export-name')){const blob=await operation('profiles',{name:target.dataset.exportName},false);const link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download='openvpn-'+(target.dataset.exportName||'all')+'.zip';link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);}
if(target.hasAttribute('data-link-name')){const result=await operation('link',{name:target.dataset.linkName},false);const url=new URL(result.url);if(url.protocol!=='https:')throw Error('Сервер вернул ссылку без HTTPS.');modal('Ссылка готова',`<p>Пользователей: ${esc(result.count)} · до ${esc(new Date(result.expires*1000).toLocaleTimeString())}</p><input readonly aria-label="Ссылка для скачивания" value="${esc(url.href)}"><p>Скопируйте ссылку и откройте на нужном устройстве.</p>`);}
if(target.dataset.deleteUser){const name=target.dataset.deleteUser;modal('Удалить пользователя?',`<p>Будут отозваны сертификат и доступ, удалены профили и пароль. Активные соединения будут отключены.</p><label>Введите логин ${esc(name)}<input id="deleteConfirmation" required autocomplete="off"></label>`,'Удалить на сервере',async d=>{await operation('delete',{name,confirmation:d.querySelector('#deleteConfirmation').value});toast('Пользователь удалён.');});}
if(a==='add-user')modal('Новый пользователь','<label>Логин<input id="newName" required pattern="[A-Za-z0-9_-]{1,48}" maxlength="48" autocomplete="off"></label><label>Комментарий<input id="newComment" maxlength="200"></label><p>На сервере будут созданы сертификат, пароль и профили UDP/TCP.</p>','Создать на сервере',async d=>{await operation('create',{name:d.querySelector('#newName').value,comment:d.querySelector('#newComment').value});toast('Пользователь создан. Откройте «Управлять», чтобы получить пароль и профили.');});
if(a==='all-profiles')profiles('');
if(a==='add-route')modal('Добавить IP / CIDR','<label>Публичный IPv4 или подсеть<input id="newRoute" required autocomplete="off"></label><p>Маршрут будет применён на российском сервере.</p>','Добавить',async d=>{await operation('route-change',{kind:routeTab,action:'add',cidr:d.querySelector('#newRoute').value.trim()});});
if(target.hasAttribute('data-remove-route')){const cidr=lists[routeTab][Number(target.dataset.removeRoute)],kind=routeTab;modal('Удалить маршрут?',`<p>${esc(cidr)}</p>`,'Удалить',async()=>{await operation('route-change',{kind,action:'remove',cidr});});}
if(a==='update-iplist'){await operation('iplist-update');toast('IPList обновлён на сервере. Переподключите VPN-клиенты.');}
}catch(error){toast(error.message);}});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!busy)document.querySelector('.admin-modal')?.remove();});
el('modeConnection').onclick=()=>setMode('connection');el('modeInstall').onclick=()=>setMode('install');el('modeAdmin').onclick=()=>setMode('admin');
qrcode.stringToBytes=qrcode.stringToBytesFuncs['UTF-8'];
window.addEventListener('vpnai-session-ended',()=>{connectionReady=false;clearTimeout(draftTimer);connectionDraft={ru:{},nl:{}};document.querySelector('.admin-modal')?.remove();snapshot={connected:false,servers:{},sessions:[]};updateIndicators();render();el('adminView').querySelectorAll('button,input,select,textarea').forEach(n=>n.disabled=true);});
section='overview';setMode('connection');
Promise.all([request('connection-session'),api('/api/ssh/aliases')]).then(([saved,catalog])=>{for(const role of ['ru','nl'])Object.assign(connectionDraft[role],saved.draft?.[role]||{});if(saved.draft?.eu_ssh==='via_ru'||saved.draft?.eu_ssh==='direct')connectionDraft.eu_ssh=saved.draft.eu_ssh;if(saved.draft?.eu_target==='gre'||saved.draft?.eu_target==='public')connectionDraft.eu_target=saved.draft.eu_target;draftRevision=saved.revision||0;sshAliasCatalog=catalog.aliases||[];document.querySelectorAll('[data-alias-scope=install]').forEach(menu=>{menu.innerHTML=sshAliasOptions(document.getElementById(menu.dataset.aliasRole+'Host').dataset.sshAlias||'');});connectionReady=true;hydrateSharedDraft();render();if(catalog.warnings?.length)toast(catalog.warnings.join(' '));}).catch(e=>toast(e.message));
request('status').then(acceptSnapshot).then(()=>{if(snapshot.connected&&mode==='connection')section='overview';render();}).catch(e=>toast(e.message));
setInterval(()=>{if(mode==='admin'&&snapshot.connected&&!busy&&!document.querySelector('.admin-modal')&&section!=='connection'){busy=true;refresh().catch(e=>{snapshot.connected=false;updateIndicators();toast(e.message);}).finally(()=>busy=false);}},30000);
})();

(()=>{'use strict';
const TEMPLATE=JSON.stringify({RU:{ip:'',login:'root',password:'',port:22},EU:{ip:'',login:'root',password:'',port:22}},null,2)+'\n';
const adapters=window.vpnaiServerFiles.adapters;
function notice(text){document.querySelector('.server-file-toast')?.remove();const n=document.createElement('div');n.className='toast server-file-toast';n.setAttribute('role','status');n.textContent=text;document.body.append(n);setTimeout(()=>n.remove(),6500);}
function ready(){if(adapters.length!==2||adapters.some(a=>!a.canImport()))throw Error('Дождитесь загрузки сеанса или завершения текущей операции.');}
function parse(text){
 let file;try{file=JSON.parse(text.replace(/^\uFEFF/,''));}catch{throw Error('Файл должен содержать корректный JSON. Проверьте кавычки и запятые по шаблону.');}
 if(!file||typeof file!=='object'||Array.isArray(file)||Object.keys(file).some(k=>!['RU','EU','ru','eu'].includes(k)))throw Error('Используйте два блока RU и EU из шаблона.');
 const result={};
 for(const [section,role] of [['RU','ru'],['EU','nl']]){
  if(Object.hasOwn(file,section)&&Object.hasOwn(file,section.toLowerCase()))throw Error('Блок '+section+' указан дважды.');
  const values=file[section]??file[section.toLowerCase()];
  if(!values||typeof values!=='object'||Array.isArray(values))throw Error('В файле отсутствует блок '+section+'.');
  if(Object.keys(values).some(k=>!['ip','login','password','port'].includes(k)))throw Error('В блоке '+section+' допустимы только ip, login, password и port.');
  for(const key of ['ip','login','password','port'])if(!Object.hasOwn(values,key)||values[key]==='')throw Error('Заполните поле '+key+' в блоке '+section+'.');
  const host=typeof values.ip==='string'?values.ip.trim():'',parts=host.split('.');
  if(parts.length!==4||parts.some(p=>!/^\d{1,3}$/.test(p)||Number(p)>255||String(Number(p))!==p))throw Error('В блоке '+section+' укажите корректный IPv4 в поле ip.');
  if(values.login!=='root')throw Error('Для VPNAI в поле login блока '+section+' требуется root.');
  const port=values.port;if(!['number','string'].includes(typeof port)||!/^\d+$/.test(String(port))||Number(port)<1||Number(port)>65535)throw Error('В блоке '+section+' порт должен быть от 1 до 65535.');
  const password=values.password;if(typeof password!=='string'||!password.length||password.length>4096||/[\0\r\n]/.test(password))throw Error('Некорректное поле password в блоке '+section+'.');
  result[role]={host,port:Number(port),user:'root',password,method:'password',alias:'',key:'',key_path:'~/.ssh/id_ed25519',passphrase:''};
 }
 if(result.ru.host===result.nl.host)throw Error('RU и EU должны указывать на разные серверы.');
 return result;
}
async function download(){
 const blob=new Blob([TEMPLATE],{type:'application/json;charset=utf-8'}),filename='vpnai-servers.json';
 if(typeof vpnaiSaveBlob==='function'){await vpnaiSaveBlob(blob,filename);return;}
 if(window.VPNAIAndroid){const encoded=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result).split(',')[1]);reader.onerror=()=>reject(Error('Не удалось подготовить шаблон.'));reader.readAsDataURL(blob);});window.VPNAIAndroid.saveFile(filename,'application/json',encoded);return;}
 const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=filename;link.click();setTimeout(()=>URL.revokeObjectURL(url),10000);
}
const picker=document.createElement('input');picker.type='file';picker.accept='.json,.txt,application/json,text/plain';picker.className='hidden';picker.id='serverConnectionFile';picker.setAttribute('aria-label','Загрузить файл с данными RU и EU');document.body.append(picker);
picker.addEventListener('change',async()=>{
 const file=picker.files?.[0];if(!file)return;
 try{ready();if(file.size>65536)throw Error('Файл слишком большой. Максимальный размер — 64 КиБ.');const servers=parse(await file.text());ready();for(const adapter of adapters)adapter.apply(servers);notice('Данные RU и EU подставлены в общую форму подключения и установку. Подключение не запускалось.');}
 catch(error){notice(error.message||'Не удалось прочитать файл. Используйте скачанный шаблон.');}
 finally{picker.value='';}
});
document.addEventListener('click',event=>{
 const target=event.target.closest('[data-server-file-download],[data-server-file-upload]');
 if(target){event.stopPropagation();target.closest('details').open=false;if(target.hasAttribute('data-server-file-download'))download().catch(()=>notice('Не удалось скачать шаблон.'));else{try{ready();picker.click();}catch(error){notice(error.message);}}return;}
 document.querySelectorAll('.connection-file-menu[open]').forEach(menu=>{if(!menu.contains(event.target))menu.open=false;});
},true);
document.addEventListener('keydown',event=>{if(event.key==='Escape')document.querySelectorAll('.connection-file-menu[open]').forEach(menu=>menu.open=false);});
})();

if(window.vpnaiDNSPreview.openInitially){document.getElementById('modeAdmin').click();document.querySelector('#adminNav [data-admin-page=routes]').click();}


window.addEventListener('vpnai-limits-draft',()=>{if(currentConfig)currentConfigDirty=true;if(typeof scheduleSession==='function')scheduleSession();});
