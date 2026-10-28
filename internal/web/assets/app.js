const basePath=(location.pathname.match(/^\/(?:t|portal)\/[a-z][a-z0-9-]{0,31}(?=\/)/)||[''])[0];
const scopedFetch=(path,options)=>fetch(basePath+path,options);
'use strict';
const $ = (s) => document.querySelector(s);
const csrf = $('meta[name="csrf-token"]').content;
let state;
function notice(text, error = false) { const n = $('#notice'); n.textContent = text; n.className = error ? 'error' : ''; n.hidden = false; }
const date = (t) => new Date(t * 1000).toLocaleString('ru-RU');
function table(target, heads, rows, kind) {
 const holder = $(target); holder.replaceChildren();
 if (!rows.length) { const p = document.createElement('div'); p.className = 'empty'; p.textContent = 'Пока нет записей'; holder.append(p); return; }
 const t = document.createElement('table'), thead = document.createElement('thead'), tr = document.createElement('tr');
 for (const h of heads) { const th = document.createElement('th'); th.textContent = h; tr.append(th); }
 if (kind) { const th = document.createElement('th'); th.textContent = 'Действие'; tr.append(th); }
 thead.append(tr); t.append(thead); const body = document.createElement('tbody');
 for (const row of rows) { const tr = document.createElement('tr'); for (const v of row) { const td = document.createElement('td'); td.textContent = v; tr.append(td); }
  if (kind) { const td = document.createElement('td'), b = document.createElement('button'); b.className = 'remove'; b.textContent = 'Удалить'; b.onclick = async () => { if (!confirm('Удалить запись ' + row[0] + '?')) return; await mutate('/api/delete', { Kind: kind, Key: String(row[0]) }); }; td.append(b); tr.append(td); }
  body.append(tr);
 } t.append(body); holder.append(t);
}
async function load() {
 try { const r = await scopedFetch('/api/state'); if (!r.ok) throw new Error('Не удалось загрузить данные: ' + r.status); state = await r.json();
  $('#stat-nas').textContent = state.nas.length; $('#stat-vlans').textContent = state.vlans.length; $('#stat-devices').textContent = state.devices.filter(d => d.Active).length; $('#stat-sessions').textContent = state.sessions.filter(s => s.Status === 'active').length;
  table('#nas-list', ['IP-адрес', 'Имя', 'Словарь', 'Режим', 'Расположение', 'Одиночная политика', 'CoA порт', 'SMS-портал'], state.nas.map(n => [n.Address, n.Name, n.Dictionary, n.Mode, n.LocationID, n.AccessPolicyID, n.CoAPort, n.PortalEnabled ? 'Разрешён' : 'Выключен']), 'nas');
  for(const nas of state.nas){const b=document.createElement('button');b.textContent='Изменить '+nas.Address;b.onclick=()=>fillForm('#nas-form',{...nas,Secret:''});$('#nas-list').append(b);}
  table('#vlans-list', ['VLAN', 'Название'], state.vlans.map(v => [v.ID, v.Name]), 'vlans');
  table('#devices-list', ['MAC', 'VLAN', 'Статус', 'Тип', 'Комментарий'], state.devices.map(d => [d.MAC, d.VLAN || 'NAS default', d.Active ? 'Активно' : 'Запрещено', d.Voice ? 'Voice' : 'Data', d.Comment]), 'devices');
  const revokeReason = {'user blocked':'Пользователь заблокирован','domain disabled':'Домен отключён','policy expired':'Срок политики истёк','session expired':'Срок сессии истёк','policy unavailable':'Политика отключена или недоступна','access revoked':'Доступ отозван'};
  const sessionStatus = {active:'Активна',stale:'Связь потеряна',stopped:'Завершена','nas-on':'NAS перезапущен','nas-off':'NAS выключен','disconnect-ack':'Отключение подтверждено'};
  table('#sessions-list', ['NAS', 'Сессия', 'Пользователь', 'Статус', 'Последний accounting', 'Причина отзыва', 'Попытки', 'Последняя попытка', 'Ответ NAS / ошибка', 'Следующая попытка'], state.sessions.map(s => [s.NAS,s.ID,s.Username,sessionStatus[s.Status] || s.Status,date(s.LastSeen),revokeReason[s.RevocationReason] || s.RevocationReason || '—',s.RevocationAttempts || 0,s.RevocationLast ? date(s.RevocationLast) : '—',[s.RevocationResponse,s.RevocationCause ? 'Error-Cause='+s.RevocationCause : '',s.RevocationError].filter(Boolean).join(' · ') || '—',s.RevocationReason && ['active','stale'].includes(s.Status) ? (s.RevocationNext ? date(s.RevocationNext) : 'В очереди') : '—']));
  const heads = ['Время', 'Источник', 'Идентификатор', 'Результат', 'Причина']; const rows = state.events.map(e => [date(e.Time), e.Source, e.Identity, e.Result, e.Reason]); table('#events-list', heads, rows); table('#recent', heads, rows.slice(0, 8));
  document.querySelectorAll('.vlan-select').forEach(s => { const value = s.value; while(s.options.length > 1) s.remove(1); state.vlans.forEach(v => {const o = new Option(v.ID + ' · ' + v.Name, v.ID); s.add(o);}); s.value = value; });
  $('#session-select').replaceChildren();state.sessions.filter(s=>['active','stale'].includes(s.Status)).forEach((s,i)=>$('#session-select').add(new Option(s.NAS+' · '+s.ID+' · '+s.Username,JSON.stringify({NAS:s.NAS,ID:s.ID,MAC:s.MAC,Username:s.Username,Updated:s.Updated,Generation:s.Generation}))));
  $('#settings-form').elements.Isolation.value = state.isolation;
  await loadGuest();
 await loadProfiles();
 await loadFingerprints();
 await loadFingerbank();
 await loadAccessModel();
 await loadTenants();
  const eapResponse=await scopedFetch('/api/eap');if(eapResponse.ok){const ep=await eapResponse.json();$('#eap-form').elements.Enabled.checked=ep.Enabled;$('#eap-form').elements.VLAN.value=ep.VLAN;$('#eap-status').textContent=ep.Available?'Используются управляемые CA из раздела сертификатов.':'Для EAP-TLS задайте BORDER_MASTER_KEY и перезапустите radiusd.';}
 } catch(e) { notice(e.message, true); }
}
async function mutate(url, data) { try { const r = await scopedFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: JSON.stringify(data) }); if (!r.ok) throw new Error(await r.text()); notice('Изменения сохранены'); await load(); return true; } catch(e) { notice(e.message, true); return false; } }
const navButtons=[...document.querySelectorAll('nav button[data-view]')];
function activateView(name,updateURL=false){const button=navButtons.find(b=>b.dataset.view===name && !b.hidden);if(!button)return;document.querySelectorAll('.view').forEach(v=>v.hidden=v.id!==name);for(const b of navButtons){const selected=b===button;b.classList.toggle('selected',selected);if(selected)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');}const group=button.closest('.nav-group');if(group)group.open=true;$('#breadcrumb').textContent=button.dataset.path+' / '+button.textContent.trim();if(updateURL)history.replaceState(null,'','#'+name);window.scrollTo({top:0,behavior:'instant'});}
navButtons.forEach(b=>b.onclick=()=>activateView(b.dataset.view,true));
window.addEventListener('hashchange',()=>activateView(location.hash.slice(1)));
activateView(location.hash.slice(1)||'overview');
function filterNavigation(){const q=$('#nav-search').value.trim().toLocaleLowerCase('ru');let count=0;for(const b of navButtons){const text=[b.textContent,b.dataset.path,b.dataset.keywords||''].join(' ').toLocaleLowerCase('ru');const match=!q || text.includes(q);b.classList.toggle('nav-filtered',!match);if(match && !b.hidden)count++;}for(const group of document.querySelectorAll('.nav-group')){const match=[...group.querySelectorAll('button')].some(b=>!b.hidden && !b.classList.contains('nav-filtered'));group.classList.toggle('nav-filtered',!match);if(q){if(group.dataset.previousOpen===undefined)group.dataset.previousOpen=String(group.open);group.open=match;}else if(group.dataset.previousOpen!==undefined){group.open=group.dataset.previousOpen==='true' || !!group.querySelector('[aria-current="page"]');delete group.dataset.previousOpen;}}document.querySelectorAll('.nav-label').forEach(n=>n.classList.toggle('nav-filtered',!!q));$('#nav-empty').hidden=count>0;}
$('#nav-search').oninput=filterNavigation;$('#nav-search').onkeydown=e=>{if(e.key==='Escape'){$('#nav-search').value='';filterNavigation();}};

for (const kind of ['nas', 'devices', 'vlans', 'settings']) { const form = $('#' + kind + '-form'); form.onsubmit = async e => { e.preventDefault(); const data = Object.fromEntries(new FormData(form)); for (const k of ['VLAN', 'ID', 'Isolation', 'CoAPort']) if (k in data) data[k] = Number(data[k]); if (kind === 'nas') data.PortalEnabled = form.elements.PortalEnabled.checked; if (kind === 'devices') {data.Active = form.elements.Active.checked; data.Voice = form.elements.Voice.checked;}
 if (await mutate('/api/' + kind, data)) {if(kind === 'nas') form.elements.Secret.value = '';}
 }; }
$('#refresh').onclick = () => {load();loadPKI();};
load();

function savePEM(b){const blob=new Blob([b.PrivateKey+'\n'+b.Certificate+'\n'+b.CA],{type:'application/x-pem-file'});const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='border-'+b.Serial+'.pem';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
async function pkiAPI(path,data){const r=await scopedFetch('/api/pki'+path,{method:data?'POST':'GET',headers:data?{'Content-Type':'application/json','X-CSRF-Token':csrf}:{},body:data?JSON.stringify(data):undefined});if(!r.ok)throw new Error(await r.text());return r.json();}
async function loadPKI(){try{const p=await pkiAPI('');$('#cert-ca').replaceChildren();p.authorities.forEach(c=>$('#cert-ca').add(new Option(c.Name,c.ID)));table('#ca-list',['CA ID','Имя','Создан'],p.authorities.map(c=>[c.ID,c.Name,date(c.Created)]));const holder=$('#ca-list');p.authorities.forEach(c=>{const a=document.createElement('a');a.href=basePath+'/api/pki/crl/'+encodeURIComponent(c.ID);a.textContent=' Скачать CRL: '+c.Name+' ';holder.append(a);});table('#cert-list',['Серийный номер','CA','Владелец','До','Статус'],p.certificates.map(c=>[c.Serial,c.CA,c.Owner,date(c.Expires),c.Revoked?'Отозван':'Выдан']));p.certificates.filter(c=>!c.Revoked).forEach(c=>{const b=document.createElement('button');b.textContent='Отозвать '+c.Serial;b.className='remove';b.onclick=async()=>{if(!confirm('Отозвать сертификат?'))return;try{await pkiAPI('/revoke',{Serial:c.Serial});await loadPKI();}catch(e){notice(e.message,true);}};$('#cert-list').append(b);});const f=$('#acme-form');f.hidden=p.ACMEAvailable===false;for(const k of ['Domain','Email','DirectoryURL'])f.elements[k].value=p.acme[k]||'';for(const k of ['Enabled','AcceptTerms'])f.elements[k].checked=!!p.acme[k];}catch(e){$('#ca-list').textContent=e.message;}}
$('#ca-form').onsubmit=async e=>{e.preventDefault();try{await pkiAPI('/ca',Object.fromEntries(new FormData(e.target)));e.target.reset();notice('CA сохранён');await loadPKI();}catch(e){notice(e.message,true);}};
$('#cert-form').onsubmit=async e=>{e.preventDefault();try{const data=Object.fromEntries(new FormData(e.target));data.Days=Number(data.Days);savePEM(await pkiAPI('/issue',data));notice('Сертификат и ключ скачаны');await loadPKI();}catch(e){notice(e.message,true);}};
$('#acme-form').onsubmit=async e=>{e.preventDefault();try{const f=e.target,data=Object.fromEntries(new FormData(f));data.Enabled=f.elements.Enabled.checked;data.AcceptTerms=f.elements.AcceptTerms.checked;await pkiAPI('/acme',data);notice('ACME настроен. Внешняя проверка домена выполняется при запросе сертификата.');}catch(e){notice(e.message,true);}};
loadPKI();

$("#logout").onclick=async()=>{try{await scopedFetch("/api/logout",{method:"POST",headers:{"X-CSRF-Token":csrf}});location.reload();}catch(e){notice(e.message,true);}};

$('#eap-form').onsubmit=async e=>{e.preventDefault();const f=e.target;await mutate('/api/eap',{Enabled:f.elements.Enabled.checked,VLAN:Number(f.elements.VLAN.value)});};

$('#session-action-form').onsubmit=async e=>{e.preventDefault();const f=e.target;if(!f.elements.Session.value)return;if(!confirm('Отправить действие на NAS для выбранной сессии?'))return;try{const data=JSON.parse(f.elements.Session.value);data.Action=f.elements.Action.value;data.VLAN=Number(f.elements.VLAN.value);const r=await scopedFetch('/api/sessions/action',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(data)});if(!r.ok)throw new Error(await r.text());const result=await r.json();notice(result.Queued?'Повторная попытка поставлена в очередь':result.Acknowledged?'NAS подтвердил выполнение: '+result.Code:'NAS отклонил запрос: '+result.Code+', Error-Cause='+result.ErrorCause,!result.Acknowledged && !result.Queued);await load();}catch(err){notice(err.message,true);}};

async function loadGuest(){
 try{
 const r=await scopedFetch('/api/guest/config');if(!r.ok)throw new Error(await r.text());
 const g=await r.json(),f=$('#sms-form'),p=$('#guest-policy-form');
 for(const k of ['Provider','URL','AccountSID','From','CAPEM'])f.elements[k].value=g.SMS[k]||'';
 f.elements.Token.value='';$('#sms-status').textContent=g.HasToken?'Токен сохранён в зашифрованном виде.':'Токен ещё не задан.';
 p.elements.Enabled.checked=g.Policy.Enabled;
 for(const k of ['VLAN','SessionSeconds','MaxPerHour'])p.elements[k].value=g.Policy[k];
 table('#guest-list',['NAS','MAC','Телефон','VLAN','До'],g.Sessions.map(s=>[s.NAS,s.MAC,s.MaskedPhone,s.VLAN,date(s.Expires)]));
 $('#guest-actions').replaceChildren();
 for(const s of g.Sessions){const b=document.createElement('button');b.className='remove';b.textContent='Отозвать '+s.MAC+' / '+s.NAS;b.onclick=async()=>{if(confirm('Отозвать гостевое разрешение?'))await mutate('/api/guest/revoke',{NAS:s.NAS,MAC:s.MAC});};$('#guest-actions').append(b);}
 }catch(e){$('#sms-status').textContent=e.message;}
}
$('#sms-form').onsubmit=async e=>{e.preventDefault();await mutate('/api/guest/sms',Object.fromEntries(new FormData(e.target)));};
$('#guest-policy-form').onsubmit=async e=>{e.preventDefault();const f=e.target;await mutate('/api/guest/policy',{Enabled:f.elements.Enabled.checked,VLAN:Number(f.elements.VLAN.value),SessionSeconds:Number(f.elements.SessionSeconds.value),MaxPerHour:Number(f.elements.MaxPerHour.value)});};

let dictionaries=[];
function showDictionary(){const d=dictionaries.find(d=>d.ID===$('#nas-dictionary').value);if(!d)return;$('#dictionary-notes').textContent=d.Notes;const f=$('#nas-form');for(const o of f.elements.Mode.options)o.disabled=(d.ID==='keenetic'||d.ID==='strongswan')&&o.value!=='network';if(f.elements.Mode.selectedOptions[0]?.disabled)f.elements.Mode.value='network';table('#dictionary-attributes',['Атрибут','Vendor ID','Код','Тип'],d.Attributes.map(a=>[a.Name,a.Vendor,a.Code,a.Type]));}
async function loadProfiles(){
 try{
 const r=await scopedFetch('/api/dictionaries');if(!r.ok)throw new Error(await r.text());dictionaries=await r.json();
 const select=$('#nas-dictionary'),value=select.value||'standard';select.replaceChildren();for(const d of dictionaries)select.add(new Option(d.Name,d.ID));select.value=value;showDictionary();
 const nas=$('#grant-nas'),old=nas.value;nas.replaceChildren();for(const n of state.nas.filter(n=>n.Mode!=='network'))nas.add(new Option(n.Name+' · '+n.Address+' · '+n.Mode,n.Address));if(old)nas.value=old;
 const response=await scopedFetch('/api/nas/grants');if(!response.ok)throw new Error(await response.text());const grants=await response.json();
 table('#nas-grants',['NAS','Пользователь','Режим','Уровень','Группа','Профиль','Filter-Id'],grants.map(g=>[g.NAS,g.Username,g.Mode,g.Privilege,g.Group,g.Role,g.Filter]));
 $('#nas-grant-actions').replaceChildren();for(const g of grants){const b=document.createElement('button');b.textContent='Отозвать '+g.Username+' / '+g.NAS+' / '+g.Mode;b.className='remove';b.onclick=async()=>{if(confirm('Отозвать разрешение?'))await mutate('/api/nas/grants/delete',g)};$('#nas-grant-actions').append(b);}
 }catch(e){notice(e.message,true);}
}
$('#nas-dictionary').onchange=showDictionary;
$('#nas-grant-form').onsubmit=async e=>{e.preventDefault();const d=Object.fromEntries(new FormData(e.target));d.Privilege=Number(d.Privilege);await mutate('/api/nas/grants',d);};

let fingerprints=[];
function renderFingerprints(){
 const query=$('#fingerprint-search').value.toLowerCase();
 const rows=fingerprints.filter(f=>Object.values(f).join(' ').toLowerCase().includes(query));
 table('#fingerprint-list',['MAC','NAS','Производитель / OUI','ОС','Тип','DHCP','Последний запрос'],rows.map(f=>[f.MAC,f.NAS,f.Manufacturer||f.OUIManufacturer||'Не определён',f.OS,f.DeviceType,f.DHCPOptions,date(f.LastSeen)]));
 $('#fingerprint-actions').replaceChildren();
 for(const f of rows){const b=document.createElement('button');b.textContent='Профиль '+f.MAC;b.onclick=async()=>{
 const form=$('#fingerprint-form');for(const k of ['MAC','NAS','DHCPOptions','VendorClass','Hostname','OS','Manufacturer','DeviceType'])form.elements[k].value=f[k];
 try{const r=await scopedFetch('/api/fingerprints/history?mac='+encodeURIComponent(f.MAC));if(!r.ok)throw new Error(await r.text());const h=await r.json();table('#fingerprint-history',['Время','Источник','Изменение'],h.map(v=>[date(v.Time),v.Source,v.Detail]));}catch(e){notice(e.message,true);}
 };$('#fingerprint-actions').append(b);const fb=document.createElement('button');fb.textContent='Fingerbank '+f.MAC;fb.onclick=()=>lookupFingerbank(f.MAC);$('#fingerprint-actions').append(fb);}
}
async function loadFingerprints(){try{const r=await scopedFetch('/api/fingerprints');if(!r.ok)throw new Error(await r.text());fingerprints=await r.json();renderFingerprints();}catch(e){notice(e.message,true);}}
$('#fingerprint-search').oninput=renderFingerprints;
$('#fingerprint-form').onsubmit=async e=>{e.preventDefault();await mutate('/api/fingerprints',Object.fromEntries(new FormData(e.target)));};
$('#oui-form').onsubmit=async e=>{e.preventDefault();await mutate('/api/fingerprints/oui',Object.fromEntries(new FormData(e.target)));};

async function loadFingerbank(){try{const r=await scopedFetch('/api/fingerbank/config');if(!r.ok)throw new Error(await r.text());const c=await r.json(),f=$('#fingerbank-form');f.elements.Enabled.checked=c.Enabled;f.elements.TTLHours.value=c.TTLHours;f.elements.Key.value='';$('#fingerbank-status').textContent=c.HasKey?'Ключ сохранён и скрыт.':'Ключ ещё не задан.';}catch(e){$('#fingerbank-status').textContent=e.message;}}
$('#fingerbank-form').onsubmit=async e=>{e.preventDefault();const f=e.target;await mutate('/api/fingerbank/config',{Enabled:f.elements.Enabled.checked,Key:f.elements.Key.value,TTLHours:Number(f.elements.TTLHours.value)});};
async function lookupFingerbank(mac){try{const r=await scopedFetch('/api/fingerbank/lookup',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({MAC:mac})});if(!r.ok)throw new Error(await r.text());const v=await r.json(),n=$('#fingerbank-result');n.hidden=false;n.textContent=mac+': '+(v.NotFound?'Не определено':v.DeviceName+' · достоверность '+v.Score+'/100')+' · '+(v.Stale?'Устаревший кэш':v.Cached?'Из кэша':'Получено из API')+' · '+date(v.UpdatedAt);}catch(e){notice(e.message,true);}}

function fillForm(id,data){if(id==='#authentication-form' && !data.Steps?.length)data={...data,Steps:data.RequireTOTP?['primary','totp']:['primary']};const form=$(id);for(const [key,value] of Object.entries(data)){const input=form.elements[key];if(!input)continue;if(input.type==='checkbox')input.checked=!!value;else if(input.type==='datetime-local')input.value=value?new Date(value*1000-new Date(value*1000).getTimezoneOffset()*60000).toISOString().slice(0,16):'';else input.value=Array.isArray(value)?value.join('\n'):(value??'');}form.scrollIntoView({behavior:'smooth',block:'start'});}
function editableTable(target,heads,items,columns,form){table(target,heads,items.map(columns));for(const item of items){const b=document.createElement('button');b.type='button';b.textContent='Изменить '+(item.Name||item.Username||item.ID||((item.NAS||item.LocationID)+" / "+item.SegmentID));b.onclick=()=>fillForm(form,item);$(target).append(b);}}
function selectItems(selector,items){document.querySelectorAll(selector).forEach(s=>{const old=s.value,first=s.options[0]?.value===''?s.options[0].cloneNode(true):null;s.replaceChildren();if(first)s.add(first);items.forEach(v=>s.add(new Option(v.Name+' · '+v.ID,v.ID)));if([...s.options].some(o=>o.value===old))s.value=old;});}
function renderSetup(model){
 $('#setup-scope').textContent=basePath?'Текущий тенант: '+basePath.split('/')[2]+'. Все переходы сохраняют эту область настройки.':'Область: основной тенант. Другие тенанты открываются из раздела «Тенанты».';
 $('#setup-infrastructure').textContent='Расположений: '+model.Locations.length+' · Сегментов: '+model.Segments.length+' · Сопоставлений VLAN: '+model.Mappings.length;
 $('#setup-identities').textContent='Включённых доменов: '+model.Domains.filter(x=>x.Enabled).length+' · Включённых локальных пользователей: '+model.Users.filter(x=>x.Enabled).length;
 $('#setup-authentication').textContent='Включённых политик авторизации: '+model.Authentication.filter(x=>x.Enabled).length;
 $('#setup-access').textContent='Включённых политик доступа: '+model.Access.filter(x=>x.Enabled).length+'. Сроки действия проверяются отдельно.';
 $('#setup-nas').textContent='Зарегистрированных NAS: '+(state?.nas.length||0);
}
async function loadAccessModel(){
 const response=await scopedFetch('/api/access-model');if(!response.ok)throw new Error(await response.text());const model=await response.json();
 renderSetup(model);
 renderRuleModel(model);
 renderBindingChoices(model);
 selectItems('.location-select',model.Locations);selectItems('.segment-select',model.Segments);selectItems('.authentication-select',model.Authentication);selectItems('.access-select',model.Access);selectItems('.domain-select',model.Domains);
 editableTable('#authentication-list',['ID','Название','Источник','Домен','Цепочка','Состояние'],model.Authentication,a=>[a.ID,a.Name,a.Source,a.DomainID,(a.Steps?.length?a.Steps:(a.RequireTOTP?['primary','totp']:['primary'])).map(s=>({primary:'Основная',device:'Устройство',totp:'TOTP'}[s])).join(' → '),a.Enabled?'Включена':'Выключена'],'#authentication-form');
 editableTable('#access-list',['ID','Название','Авторизация','Назначение','Сегмент','Действует до','Сессия, сек','Разрешено','Состояние'],model.Access,a=>[a.ID,a.Name,a.AuthenticationID,a.Mode,a.SegmentID,a.ValidUntil?date(a.ValidUntil):'Без ограничения',a.SessionSeconds,a.Subjects.join(', '),a.Enabled?'Включена':'Выключена'],'#access-form');
 editableTable('#location-list',['ID','Расположение'],model.Locations,a=>[a.ID,a.Name],'#location-form');editableTable('#segment-list',['ID','Сегмент'],model.Segments,a=>[a.ID,a.Name],'#segment-form');
 editableTable('#mapping-list',['Расположение','NAS (переопределение)','Сегмент','VLAN'],model.Mappings,a=>[a.LocationID,a.NAS,a.SegmentID,a.VLAN],'#mapping-form');
 editableTable('#domain-list',['ID','Название','LDAP-серверы','Атрибут','Состояние','Пароль'],model.Domains,a=>[a.ID,a.Name,a.Endpoints.join(', '),a.UserAttribute,a.Enabled?'Включён':'Выключен',a.HasPassword?'Сохранён':'Не задан'],'#domain-form');
 editableTable('#local-user-list',['Логин','Почта','Телефон','Состояние'],model.Users,a=>['local/'+a.Username,a.Email,a.Phone,a.Enabled?'Включён':'Выключен'],'#local-user-form');
 const scope=$('#notification-scope'),value=scope.value;scope.replaceChildren(new Option('Тенант · по умолчанию / локальные пользователи','default'));for(const d of model.Domains)scope.add(new Option(d.Name+' · '+d.ID,d.ID));scope.value=[...scope.options].some(o=>o.value===value)?value:'default';
 $('#selfservice-link').href='/portal/'+(basePath?basePath.split('/')[2]:'default')+'/';
 await loadNotificationConfig();
}
async function loadTenants(){const r=await scopedFetch('/api/tenants');if(r.status===404){$('#tenants-nav').hidden=true;return;}if(!r.ok)throw new Error(await r.text());const items=await r.json();$('#tenants-nav').hidden=false;$('#setup-tenants').hidden=false;if(location.hash==='#tenants')activateView('tenants');filterNavigation();table('#tenant-list',['ID','Название'],items.map(t=>[t.ID,t.Name]));$('#tenant-links').replaceChildren();for(const t of items){const a=document.createElement('a');a.href='/t/'+encodeURIComponent(t.ID)+'/';a.textContent='Открыть '+t.Name;a.className='tenant-link';$('#tenant-links').append(a);}}
for(const [formId,path] of Object.entries({'authentication-form':'authentication-policies','access-form':'access-policies','location-form':'locations','segment-form':'network_segments','mapping-form':'segment-mappings','domain-form':'domains','local-user-form':'local-users','tenant-form':'tenants'})){
 $('#'+formId).onsubmit=async e=>{e.preventDefault();const form=e.target,data=Object.fromEntries(new FormData(form));for(const el of form.elements)if(el.name){if(el.type==='checkbox')data[el.name]=el.checked;if(el.type==='number')data[el.name]=Number(el.value);if(el.type==='datetime-local')data[el.name]=el.value?Math.floor(new Date(el.value).getTime()/1000):0;}
 for(const key of ['Subjects','Endpoints','Steps'])if(key in data)data[key]=data[key].split('\n').map(v=>v.trim()).filter(Boolean);
 if(await mutate('/api/'+path,data)){for(const key of ['Password','BindPassword'])if(form.elements[key])form.elements[key].value='';await loadTenants();}
 };
}
async function loadNotificationConfig(){const r=await scopedFetch('/api/notifications?scope='+encodeURIComponent($('#notification-scope').value));if(!r.ok)throw new Error(await r.text());const c=await r.json(),f=$('#notifications-form');for(const channel of ['SMTP','SMS','Push']){for(const [key,value] of Object.entries(c[channel])){const el=f.elements[channel+key];if(el){if(el.type==='checkbox')el.checked=!!value;else el.value=value??'';}}f.elements[channel+'Mode'].querySelector('[value="inherit"]').disabled=c.Scope==='default';}f.elements.SMTPPassword.value='';f.elements.SMSToken.value='';$('#notifications-status').textContent='SMTP: '+(c.SMTP.HasPassword?'пароль сохранён':'пароль не задан')+' · SMS: '+(c.SMS.HasToken?'токен сохранён':'токен не задан')+' · Push: '+(c.Push.PublicKey?'ключ создан':'ключ ещё не создан');}
$('#notification-scope').onchange=()=>loadNotificationConfig().catch(e=>notice(e.message,true));
$('#notifications-form').onsubmit=async e=>{e.preventDefault();const f=e.target,data={Scope:f.elements.Scope.value,SMTP:{},SMS:{},Push:{}};for(const el of f.elements){if(!el.name || el.name==='Scope')continue;const channel=['SMTP','SMS','Push'].find(c=>el.name.startsWith(c));if(channel)data[channel][el.name.slice(channel.length)]=el.type==='checkbox'?el.checked:el.value;}await mutate('/api/notifications',data);};

let ruleSets=[],ruleDraft=null,rulesDirty=false;
const ruleArrays=['Subjects','Groups','DirectoryGroups','NAS','Locations','SSIDs','OS','DeviceTypes','Manufacturers'];
function renderRuleModel(model){
 editableTable('#user-group-list',['ID','Название','Участники','Состояние'],model.Groups,g=>[g.ID,g.Name,g.Members.join(', '),g.Enabled?'Включена':'Выключена'],'#user-group-form');
 ruleSets=model.RuleSets;selectItems('.rule-policy-select',model.Access);if(!rulesDirty)selectRuleDraft();
}
function selectRuleDraft(){const id=$('#rule-policy').value;ruleDraft=id?structuredClone(ruleSets.find(r=>r.PolicyID===id)||{PolicyID:id,Version:0,Enabled:false,Rules:[]}):null;rulesDirty=false;renderRuleDraft();}
function renderRuleDraft(){
 $('#rules-enabled').checked=!!ruleDraft?.Enabled;$('#save-rules').disabled=!ruleDraft;
 $('#rules-status').textContent=!ruleDraft?'Выберите политику':rulesDirty?'Черновик изменён, изменения ещё не применены.':'Версия набора: '+ruleDraft.Version;
 const rules=(ruleDraft?.Rules||[]).toSorted((a,b)=>a.Priority-b.Priority);
 table('#rule-list',['Приоритет','ID','Название','Действие','Состояние'],rules.map(r=>[r.Priority,r.ID,r.Name,r.Effect==='allow'?'Разрешить':'Запретить',r.Enabled?'Включено':'Выключено']));
 for(const rule of rules){const edit=document.createElement('button');edit.type='button';edit.textContent='Изменить '+rule.ID;edit.onclick=()=>fillForm('#access-rule-form',Object.fromEntries(Object.entries({...Object.fromEntries(ruleArrays.map(k=>[k,[]])),...rule}).map(([k,v])=>[k,v??[]])));const remove=document.createElement('button');remove.type='button';remove.textContent='Убрать из черновика '+rule.ID;remove.onclick=()=>{ruleDraft.Rules=ruleDraft.Rules.filter(r=>r.ID!==rule.ID);rulesDirty=true;renderRuleDraft();};$('#rule-list').append(edit,remove);}
}
$('#rule-policy').onchange=()=>{if(rulesDirty&&!confirm('Отбросить несохранённые изменения правил?')){$('#rule-policy').value=ruleDraft.PolicyID;return;}selectRuleDraft();};
$('#rules-enabled').onchange=e=>{if(!ruleDraft){e.target.checked=false;return;}ruleDraft.Enabled=e.target.checked;rulesDirty=true;renderRuleDraft();};
$('#reset-rules').onclick=()=>{if(!rulesDirty||confirm('Отбросить изменения черновика?'))selectRuleDraft();};
$('#access-rule-form').onsubmit=e=>{e.preventDefault();if(!ruleDraft){notice('Сначала выберите политику доступа',true);return;}const f=e.target,r=Object.fromEntries(new FormData(f));for(const key of ruleArrays)r[key]=r[key].split('\n').map(v=>key==='SSIDs'?v:v.trim()).filter(Boolean);r.Priority=Number(r.Priority);r.Enabled=f.elements.Enabled.checked;r.AllAuthenticated=f.elements.AllAuthenticated.checked;if(ruleDraft.Rules.some(v=>v.ID!==r.ID&&v.Priority===r.Priority)){notice('Приоритет должен быть уникальным в этом наборе',true);return;}ruleDraft.Rules=ruleDraft.Rules.filter(v=>v.ID!==r.ID);ruleDraft.Rules.push(r);rulesDirty=true;renderRuleDraft();notice('Правило добавлено в черновик. Примените набор, чтобы сохранить.');};
$('#save-rules').onclick=async()=>{if(ruleDraft&&await mutate('/api/access-rules',ruleDraft)){rulesDirty=false;selectRuleDraft();}};
$('#user-group-form').onsubmit=async e=>{e.preventDefault();const f=e.target,data=Object.fromEntries(new FormData(f));data.Members=data.Members.split('\n').map(v=>v.trim()).filter(Boolean);data.Enabled=f.elements.Enabled.checked;await mutate('/api/user-groups',data);};

let bindingsDraft=null,bindingsDirty=false,bindingsLoad=0,bindingsSaving=false;
function renderBindingChoices(model){
 const select=$('#bindings-nas'),old=select.value;select.replaceChildren(new Option('Выберите NAS',''));for(const n of state.nas)select.add(new Option(n.Name+' · '+n.Address,n.Address));if([...select.options].some(o=>o.value===old))select.value=old;
 const source=$('#binding-source'),value=source.value;source.replaceChildren(new Option('Любой / без префикса',''),new Option('Локальные пользователи','local'));for(const d of model.Domains)source.add(new Option(d.Name,d.ID));source.value=value;
 if(!bindingsDirty && select.value)loadBindings().catch(e=>notice(e.message,true));
}
async function loadBindings(){const nas=$('#bindings-nas').value,request=++bindingsLoad;bindingsDraft=null;bindingsDirty=false;renderBindings();if(!nas)return;const r=await scopedFetch('/api/nas-policies?nas='+encodeURIComponent(nas));if(!r.ok)throw new Error(await r.text());const loaded=await r.json();if(request!==bindingsLoad || $('#bindings-nas').value!==nas)return;bindingsDraft=loaded;renderBindings();}
function renderBindings(){const b=bindingsDraft;$('#bindings-enabled').checked=!!b?.Enabled;$('#bindings-status').textContent=b?'Версия '+b.Version+(bindingsDirty?' · есть неприменённые изменения':' · сохранено'):'';table('#bindings-list',['ID','Приоритет','Политика','Протокол','Домен','SSID','Service-Type','NAS-Port-Type','Включена'],(b?.Bindings||[]).map(v=>[v.ID,v.Priority,v.PolicyID,v.Protocol,v.IdentitySource||'Любой',v.SSID||'Любой',v.ServiceType||'Любой',v.NASPortType??'Любой',v.Enabled?'Да':'Нет']));for(const v of b?.Bindings||[]){const edit=document.createElement('button');edit.type='button';edit.textContent='Изменить '+v.ID;edit.onclick=()=>fillForm('#binding-form',v);const remove=document.createElement('button');remove.type='button';remove.textContent='Убрать '+v.ID;remove.onclick=()=>{b.Bindings=b.Bindings.filter(x=>x.ID!==v.ID);bindingsDirty=true;bindingsLoad++;renderBindings();};$('#bindings-list').append(edit,remove);}}
$('#bindings-nas').onchange=()=>{if(bindingsDirty && !confirm('Отбросить изменения черновика?')){$('#bindings-nas').value=bindingsDraft.NAS;return;}loadBindings().catch(e=>notice(e.message,true));};
$('#bindings-enabled').onchange=()=>{if(bindingsDraft){bindingsDraft.Enabled=$('#bindings-enabled').checked;bindingsDirty=true;bindingsLoad++;renderBindings();}};
$('#binding-form').onsubmit=e=>{e.preventDefault();if(!bindingsDraft){notice('Выберите NAS',true);return;}const f=e.target,v=Object.fromEntries(new FormData(f));v.Priority=Number(v.Priority);v.ServiceType=Number(v.ServiceType);v.NASPortType=v.NASPortType===''?null:Number(v.NASPortType);v.Enabled=f.elements.Enabled.checked;bindingsDraft.Bindings=bindingsDraft.Bindings.filter(x=>x.ID!==v.ID);bindingsDraft.Bindings.push(v);bindingsDraft.Bindings.sort((a,b)=>a.Priority-b.Priority);bindingsDirty=true;bindingsLoad++;renderBindings();};
$('#bindings-reset').onclick=()=>{if(!bindingsDirty || confirm('Отбросить изменения черновика?'))loadBindings().catch(e=>notice(e.message,true));};
$('#bindings-save').onclick=async()=>{if(!bindingsDraft || bindingsSaving)return;const saved=JSON.parse(JSON.stringify(bindingsDraft)),request=++bindingsLoad;bindingsSaving=true;$('#bindings-save').disabled=true;try{const r=await scopedFetch('/api/nas-policies',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(saved)});if(!r.ok)throw new Error(await r.text());if(bindingsDraft?.NAS===saved.NAS && bindingsDraft.Version===saved.Version){bindingsDraft.Version=saved.Version+1;if(request===bindingsLoad)bindingsDirty=false;renderBindings();}notice('Набор политик '+saved.NAS+' применён');}catch(e){notice(e.message,true);}finally{bindingsSaving=false;$('#bindings-save').disabled=false;}};
