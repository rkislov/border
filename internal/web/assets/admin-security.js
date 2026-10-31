// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
'use strict';
(()=>{
 const base=(location.pathname.match(/^\/t\/[a-z][a-z0-9-]{0,31}(?=\/)/)||[''])[0];
 const csrfToken=document.querySelector('meta[name="csrf-token"]').content;
 const $=s=>document.querySelector(s),message=$('#security-message');
 const begin=$('#mfa-begin'),confirmForm=$('#mfa-confirm'),manage=$('#mfa-manage'),create=$('#monitoring-create'),revoke=$('#monitoring-revoke');
 let busy=false;
 const say=(s,error=false)=>{message.textContent=s;message.classList.toggle('error',error);};
 async function api(path,body){const r=await fetch(base+path,body?{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrfToken},body:JSON.stringify(body)}:{});if(!r.ok)throw Error(await r.text());return r.json();}
 const clearProof=f=>{for(const n of ['Password','Code'])if(f.elements[n])f.elements[n].value='';};
 function hideRecovery(){$('#mfa-recovery-values').textContent='';$('#mfa-recovery-result').hidden=true;}
 function hideToken(){$('#monitoring-value').value='';$('#monitoring-result').hidden=true;}
 function hideEnrollment(){confirmForm.hidden=true;$('#mfa-secret').value='';$('#mfa-qr').removeAttribute('src');clearProof(confirmForm);}
 async function act(fn){if(busy)return;busy=true;say('');try{await fn();}catch(e){say(e.message,true);}finally{busy=false;}}
 async function load(){const [me,v]=await Promise.all([api('/api/me'),api('/api/admin-security')]);
  $('#security-status').textContent=me.Username+' · '+(v.Enabled?'MFA включена · осталось резервных кодов: '+v.RecoveryRemaining:'MFA не подключена')+(v.Available?'':' · ключ шифрования не настроен');
  begin.hidden=v.Enabled;begin.querySelector('button').disabled=!v.Available;manage.hidden=!v.Enabled;
  $('#monitoring-controls').hidden=!['admin','platform_admin'].includes(me.Role);
  for(const label of document.querySelectorAll('.monitoring-factor')){label.hidden=!v.Enabled;label.querySelector('input').required=v.Enabled;}
  if(!$('#monitoring-controls').hidden){const tokens=await api('/api/monitoring-tokens'),list=$('#monitoring-list');list.replaceChildren();
   if(!tokens.length){list.textContent='Токенов пока нет.';}
   for(const t of tokens){const row=document.createElement('article');row.className='draft-entry';const title=document.createElement('h3');title.textContent=t.Name+' · '+(t.Active?'Действует':t.RevokedAt?'Отозван':'Недействителен');row.append(title);const p=document.createElement('p');p.textContent=t.Scopes.join(', ')+' · владелец: '+t.CreatedBy+' · до '+new Date(t.ExpiresAt*1000).toLocaleString()+' · последнее использование: '+(t.LastUsedAt?new Date(t.LastUsedAt*1000).toLocaleString():'ещё не использован');row.append(p);
    if(t.Active){const b=document.createElement('button');b.type='button';b.textContent='Отозвать';b.onclick=()=>{revoke.elements.ID.value=t.ID;$('#monitoring-revoke-name').textContent=t.Name;clearProof(revoke);revoke.hidden=false;revoke.elements.Password.focus();};row.append(b);}list.append(row);
   }
  }
 }
 begin.onsubmit=e=>{e.preventDefault();act(async()=>{const body={Password:begin.elements.Password.value};clearProof(begin);const v=await api('/api/admin-security/begin',body);hideRecovery();$('#mfa-secret').value=v.Secret;$('#mfa-qr').src=v.QR;confirmForm.hidden=false;confirmForm.elements.Password.focus();say('Добавьте ключ в приложение и подтвердите код.');});};
 function showCodes(codes){hideRecovery();if(codes?.length){$('#mfa-recovery-values').textContent=codes.join('\n');$('#mfa-recovery-result').hidden=false;}}
 confirmForm.onsubmit=e=>{e.preventDefault();act(async()=>{const body=Object.fromEntries(new FormData(confirmForm));clearProof(confirmForm);const v=await api('/api/admin-security/confirm',body);hideEnrollment();showCodes(v.RecoveryCodes);await load();say('MFA включена. Сохраните резервные коды.');});};
 manage.onsubmit=e=>{e.preventDefault();const action=e.submitter.value;if(action==='disable'&&!window.confirm('Отключить второй фактор для вашей учётной записи? Резервные коды, прежние сессии и токены мониторинга будут аннулированы.'))return;act(async()=>{const body=Object.fromEntries(new FormData(manage));clearProof(manage);const v=await api('/api/admin-security/'+action,body);hideToken();showCodes(v.RecoveryCodes);await load();say(action==='disable'?'MFA отключена.':'Резервные коды перевыпущены. Прежние коды, сессии и токены недействительны.');});};
 create.onsubmit=e=>{e.preventDefault();act(async()=>{const f=create.elements;const body={Name:f.Name.value,ExpiresAt:Math.floor(Date.now()/1000)+Number(f.Days.value)*86400,Scopes:[...(f.Metrics.checked?['metrics:read']:[]),...(f.Health.checked?['health:read']:[])],Password:f.Password.value,Code:f.Code.value};clearProof(create);hideToken();const v=await api('/api/monitoring-tokens',body);$('#monitoring-value').value=v.Token;$('#monitoring-result').hidden=false;await load();say('Токен выпущен. Сохраните его: повторно значение не показывается.');});};
 revoke.onsubmit=e=>{e.preventDefault();act(async()=>{const body=Object.fromEntries(new FormData(revoke));clearProof(revoke);await api('/api/monitoring-tokens/revoke',body);revoke.hidden=true;await load();say('Токен отозван.');});};
 $('#monitoring-cancel').onclick=()=>{clearProof(revoke);revoke.hidden=true;};$('#mfa-hide-recovery').onclick=hideRecovery;$('#monitoring-hide').onclick=hideToken;
 function clearSensitive(){hideToken();hideRecovery();hideEnrollment();for(const f of [begin,manage,create,revoke])clearProof(f);}
 function active(){if(location.pathname.endsWith('/account/security')||location.hash==='#admin-security'){load().catch(e=>say(e.message,true));}else{clearSensitive();}}
 for(const button of document.querySelectorAll('[data-view]'))button.addEventListener('click',()=>{if(button.dataset.view==='admin-security')load().catch(e=>say(e.message,true));else clearSensitive();});
 window.addEventListener('hashchange',active);active();
})();
