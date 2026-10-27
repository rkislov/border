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
 try { const r = await fetch('/api/state'); if (!r.ok) throw new Error('Не удалось загрузить данные: ' + r.status); state = await r.json();
  $('#stat-nas').textContent = state.nas.length; $('#stat-vlans').textContent = state.vlans.length; $('#stat-devices').textContent = state.devices.filter(d => d.Active).length; $('#stat-sessions').textContent = state.sessions.filter(s => s.Status === 'active').length;
  table('#nas-list', ['IP-адрес', 'Имя', 'Словарь', 'Режим', 'CoA порт', 'SMS-портал'], state.nas.map(n => [n.Address, n.Name, n.Dictionary, n.Mode, n.CoAPort, n.PortalEnabled ? 'Разрешён' : 'Выключен']), 'nas');
  table('#vlans-list', ['VLAN', 'Название'], state.vlans.map(v => [v.ID, v.Name]), 'vlans');
  table('#devices-list', ['MAC', 'VLAN', 'Статус', 'Тип', 'Комментарий'], state.devices.map(d => [d.MAC, d.VLAN || 'NAS default', d.Active ? 'Активно' : 'Запрещено', d.Voice ? 'Voice' : 'Data', d.Comment]), 'devices');
  table('#sessions-list', ['NAS', 'Сессия', 'MAC', 'Пользователь', 'Статус', 'Обновлено'], state.sessions.map(s => [s.NAS, s.ID, s.MAC, s.Username, s.Status, date(s.Updated)]));
  const heads = ['Время', 'Источник', 'Идентификатор', 'Результат', 'Причина']; const rows = state.events.map(e => [date(e.Time), e.Source, e.Identity, e.Result, e.Reason]); table('#events-list', heads, rows); table('#recent', heads, rows.slice(0, 8));
  document.querySelectorAll('.vlan-select').forEach(s => { const value = s.value; while(s.options.length > 1) s.remove(1); state.vlans.forEach(v => {const o = new Option(v.ID + ' · ' + v.Name, v.ID); s.add(o);}); s.value = value; });
  $('#session-select').replaceChildren();state.sessions.filter(s=>s.Status==='active').forEach((s,i)=>$('#session-select').add(new Option(s.NAS+' · '+s.ID+' · '+s.Username,JSON.stringify({NAS:s.NAS,ID:s.ID,MAC:s.MAC,Username:s.Username,Updated:s.Updated}))));
  $('#settings-form').elements.Isolation.value = state.isolation;
  await loadGuest();
 await loadProfiles();
 await loadFingerprints();
 await loadFingerbank();
  const eapResponse=await fetch('/api/eap');if(eapResponse.ok){const ep=await eapResponse.json();$('#eap-form').elements.Enabled.checked=ep.Enabled;$('#eap-form').elements.VLAN.value=ep.VLAN;$('#eap-status').textContent=ep.Available?'Используются управляемые CA из раздела сертификатов.':'Для EAP-TLS задайте BORDER_MASTER_KEY и перезапустите radiusd.';}
 } catch(e) { notice(e.message, true); }
}
async function mutate(url, data) { try { const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: JSON.stringify(data) }); if (!r.ok) throw new Error(await r.text()); notice('Изменения сохранены'); await load(); return true; } catch(e) { notice(e.message, true); return false; } }
document.querySelectorAll('nav button').forEach(b => b.onclick = () => { document.querySelectorAll('.view').forEach(v => v.hidden = v.id !== b.dataset.view); document.querySelectorAll('nav button').forEach(n => n.classList.toggle('selected', n === b)); $('#breadcrumb').textContent = b.childNodes[0].textContent.trim().toUpperCase(); });
for (const kind of ['nas', 'devices', 'vlans', 'settings']) { const form = $('#' + kind + '-form'); form.onsubmit = async e => { e.preventDefault(); const data = Object.fromEntries(new FormData(form)); for (const k of ['VLAN', 'ID', 'Isolation', 'CoAPort']) if (k in data) data[k] = Number(data[k]); if (kind === 'nas') data.PortalEnabled = form.elements.PortalEnabled.checked; if (kind === 'devices') {data.Active = form.elements.Active.checked; data.Voice = form.elements.Voice.checked;}
 if (await mutate('/api/' + kind, data)) {if(kind === 'nas') form.elements.Secret.value = '';}
 }; }
$('#refresh').onclick = () => {load();loadPKI();};
load();

function savePEM(b){const blob=new Blob([b.PrivateKey+'\n'+b.Certificate+'\n'+b.CA],{type:'application/x-pem-file'});const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='border-'+b.Serial+'.pem';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
async function pkiAPI(path,data){const r=await fetch('/api/pki'+path,{method:data?'POST':'GET',headers:data?{'Content-Type':'application/json','X-CSRF-Token':csrf}:{},body:data?JSON.stringify(data):undefined});if(!r.ok)throw new Error(await r.text());return r.json();}
async function loadPKI(){try{const p=await pkiAPI('');$('#cert-ca').replaceChildren();p.authorities.forEach(c=>$('#cert-ca').add(new Option(c.Name,c.ID)));table('#ca-list',['CA ID','Имя','Создан'],p.authorities.map(c=>[c.ID,c.Name,date(c.Created)]));const holder=$('#ca-list');p.authorities.forEach(c=>{const a=document.createElement('a');a.href='/api/pki/crl/'+encodeURIComponent(c.ID);a.textContent=' Скачать CRL: '+c.Name+' ';holder.append(a);});table('#cert-list',['Серийный номер','CA','Владелец','До','Статус'],p.certificates.map(c=>[c.Serial,c.CA,c.Owner,date(c.Expires),c.Revoked?'Отозван':'Выдан']));p.certificates.filter(c=>!c.Revoked).forEach(c=>{const b=document.createElement('button');b.textContent='Отозвать '+c.Serial;b.className='remove';b.onclick=async()=>{if(!confirm('Отозвать сертификат?'))return;try{await pkiAPI('/revoke',{Serial:c.Serial});await loadPKI();}catch(e){notice(e.message,true);}};$('#cert-list').append(b);});const f=$('#acme-form');for(const k of ['Domain','Email','DirectoryURL'])f.elements[k].value=p.acme[k]||'';for(const k of ['Enabled','AcceptTerms'])f.elements[k].checked=!!p.acme[k];}catch(e){$('#ca-list').textContent=e.message;}}
$('#ca-form').onsubmit=async e=>{e.preventDefault();try{await pkiAPI('/ca',Object.fromEntries(new FormData(e.target)));e.target.reset();notice('CA сохранён');await loadPKI();}catch(e){notice(e.message,true);}};
$('#cert-form').onsubmit=async e=>{e.preventDefault();try{const data=Object.fromEntries(new FormData(e.target));data.Days=Number(data.Days);savePEM(await pkiAPI('/issue',data));notice('Сертификат и ключ скачаны');await loadPKI();}catch(e){notice(e.message,true);}};
$('#acme-form').onsubmit=async e=>{e.preventDefault();try{const f=e.target,data=Object.fromEntries(new FormData(f));data.Enabled=f.elements.Enabled.checked;data.AcceptTerms=f.elements.AcceptTerms.checked;await pkiAPI('/acme',data);notice('ACME настроен. Внешняя проверка домена выполняется при запросе сертификата.');}catch(e){notice(e.message,true);}};
loadPKI();

$("#logout").onclick=async()=>{try{await fetch("/api/logout",{method:"POST",headers:{"X-CSRF-Token":csrf}});location.reload();}catch(e){notice(e.message,true);}};

$('#eap-form').onsubmit=async e=>{e.preventDefault();const f=e.target;await mutate('/api/eap',{Enabled:f.elements.Enabled.checked,VLAN:Number(f.elements.VLAN.value)});};

$('#session-action-form').onsubmit=async e=>{e.preventDefault();const f=e.target;if(!f.elements.Session.value)return;if(!confirm('Отправить действие на NAS для выбранной сессии?'))return;try{const data=JSON.parse(f.elements.Session.value);data.Action=f.elements.Action.value;data.VLAN=Number(f.elements.VLAN.value);const r=await fetch('/api/sessions/action',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(data)});if(!r.ok)throw new Error(await r.text());const result=await r.json();notice(result.Acknowledged?'NAS подтвердил выполнение: '+result.Code:'NAS отклонил запрос: '+result.Code+', Error-Cause='+result.ErrorCause,!result.Acknowledged);await load();}catch(err){notice(err.message,true);}};

async function loadGuest(){
 try{
 const r=await fetch('/api/guest/config');if(!r.ok)throw new Error(await r.text());
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
 const r=await fetch('/api/dictionaries');if(!r.ok)throw new Error(await r.text());dictionaries=await r.json();
 const select=$('#nas-dictionary'),value=select.value||'standard';select.replaceChildren();for(const d of dictionaries)select.add(new Option(d.Name,d.ID));select.value=value;showDictionary();
 const nas=$('#grant-nas'),old=nas.value;nas.replaceChildren();for(const n of state.nas.filter(n=>n.Mode!=='network'))nas.add(new Option(n.Name+' · '+n.Address+' · '+n.Mode,n.Address));if(old)nas.value=old;
 const response=await fetch('/api/nas/grants');if(!response.ok)throw new Error(await response.text());const grants=await response.json();
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
 try{const r=await fetch('/api/fingerprints/history?mac='+encodeURIComponent(f.MAC));if(!r.ok)throw new Error(await r.text());const h=await r.json();table('#fingerprint-history',['Время','Источник','Изменение'],h.map(v=>[date(v.Time),v.Source,v.Detail]));}catch(e){notice(e.message,true);}
 };$('#fingerprint-actions').append(b);const fb=document.createElement('button');fb.textContent='Fingerbank '+f.MAC;fb.onclick=()=>lookupFingerbank(f.MAC);$('#fingerprint-actions').append(fb);}
}
async function loadFingerprints(){try{const r=await fetch('/api/fingerprints');if(!r.ok)throw new Error(await r.text());fingerprints=await r.json();renderFingerprints();}catch(e){notice(e.message,true);}}
$('#fingerprint-search').oninput=renderFingerprints;
$('#fingerprint-form').onsubmit=async e=>{e.preventDefault();await mutate('/api/fingerprints',Object.fromEntries(new FormData(e.target)));};
$('#oui-form').onsubmit=async e=>{e.preventDefault();await mutate('/api/fingerprints/oui',Object.fromEntries(new FormData(e.target)));};

async function loadFingerbank(){try{const r=await fetch('/api/fingerbank/config');if(!r.ok)throw new Error(await r.text());const c=await r.json(),f=$('#fingerbank-form');f.elements.Enabled.checked=c.Enabled;f.elements.TTLHours.value=c.TTLHours;f.elements.Key.value='';$('#fingerbank-status').textContent=c.HasKey?'Ключ сохранён и скрыт.':'Ключ ещё не задан.';}catch(e){$('#fingerbank-status').textContent=e.message;}}
$('#fingerbank-form').onsubmit=async e=>{e.preventDefault();const f=e.target;await mutate('/api/fingerbank/config',{Enabled:f.elements.Enabled.checked,Key:f.elements.Key.value,TTLHours:Number(f.elements.TTLHours.value)});};
async function lookupFingerbank(mac){try{const r=await fetch('/api/fingerbank/lookup',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({MAC:mac})});if(!r.ok)throw new Error(await r.text());const v=await r.json(),n=$('#fingerbank-result');n.hidden=false;n.textContent=mac+': '+(v.NotFound?'Не определено':v.DeviceName+' · достоверность '+v.Score+'/100')+' · '+(v.Stale?'Устаревший кэш':v.Cached?'Из кэша':'Получено из API')+' · '+date(v.UpdatedAt);}catch(e){notice(e.message,true);}}
