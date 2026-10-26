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
  table('#nas-list', ['IP-адрес', 'Имя'], state.nas.map(n => [n.Address, n.Name]), 'nas');
  table('#vlans-list', ['VLAN', 'Название'], state.vlans.map(v => [v.ID, v.Name]), 'vlans');
  table('#devices-list', ['MAC', 'VLAN', 'Статус', 'Тип', 'Комментарий'], state.devices.map(d => [d.MAC, d.VLAN || 'NAS default', d.Active ? 'Активно' : 'Запрещено', d.Voice ? 'Voice' : 'Data', d.Comment]), 'devices');
  table('#sessions-list', ['NAS', 'Сессия', 'MAC', 'Пользователь', 'Статус', 'Обновлено'], state.sessions.map(s => [s.NAS, s.ID, s.MAC, s.Username, s.Status, date(s.Updated)]));
  const heads = ['Время', 'Источник', 'Идентификатор', 'Результат', 'Причина']; const rows = state.events.map(e => [date(e.Time), e.Source, e.Identity, e.Result, e.Reason]); table('#events-list', heads, rows); table('#recent', heads, rows.slice(0, 8));
  document.querySelectorAll('.vlan-select').forEach(s => { const value = s.value; while(s.options.length > 1) s.remove(1); state.vlans.forEach(v => {const o = new Option(v.ID + ' · ' + v.Name, v.ID); s.add(o);}); s.value = value; });
  $('#settings-form').elements.Isolation.value = state.isolation;
 } catch(e) { notice(e.message, true); }
}
async function mutate(url, data) { try { const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: JSON.stringify(data) }); if (!r.ok) throw new Error(await r.text()); notice('Изменения сохранены'); await load(); return true; } catch(e) { notice(e.message, true); return false; } }
document.querySelectorAll('nav button').forEach(b => b.onclick = () => { document.querySelectorAll('.view').forEach(v => v.hidden = v.id !== b.dataset.view); document.querySelectorAll('nav button').forEach(n => n.classList.toggle('selected', n === b)); $('#breadcrumb').textContent = b.childNodes[0].textContent.trim().toUpperCase(); });
for (const kind of ['nas', 'devices', 'vlans', 'settings']) { const form = $('#' + kind + '-form'); form.onsubmit = async e => { e.preventDefault(); const data = Object.fromEntries(new FormData(form)); for (const k of ['VLAN', 'ID', 'Isolation']) if (k in data) data[k] = Number(data[k]); if (kind === 'devices') {data.Active = form.elements.Active.checked; data.Voice = form.elements.Voice.checked;}
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
