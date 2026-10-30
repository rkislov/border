const basePath=(location.pathname.match(/^\/(?:t|portal)\/[a-z][a-z0-9-]{0,31}(?=\/)/)||[''])[0];
const scopedFetch=(path,options)=>fetch(basePath+path,options);
'use strict';
const $=s=>document.querySelector(s),token=new URLSearchParams(location.search).get('token')||'';
history.replaceState(null,'',basePath+'/guest');let challenge='',design,channel='sms';
function notice(text,error=false){$('#notice').textContent=text;$('#notice').className=error?'error':'';$('#notice').hidden=false;}
async function post(path,data){const r=await scopedFetch('/api/guest/'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});if(!r.ok)throw new Error(await r.text());return r.json();}
function contactStep(){
 $('#portal-sso').hidden=!design.SSOEnabled||!(design.SSOProviders||[]).length;
 challenge='';$('#code-form').hidden=true;$('#contact-back').hidden=true;$('#phone-form').hidden=false;$('#expiry').textContent='';$('#notice').hidden=true;
 const input=$('#phone-form').elements.Contact;input.type=channel==='email'?'email':'tel';input.autocomplete=channel==='email'?'email':'tel';input.placeholder=channel==='email'?'user@example.org':'+79991234567';input.value='';
 $('#contact-label').textContent=channel==='email'?'Электронная почта':'Номер телефона';$('#phone-form button').disabled=false;input.focus();
}
$('#phone-form').elements.Channel.onchange=e=>{channel=e.target.value;contactStep();};
$('#contact-back').onclick=contactStep;
$('#phone-form').onsubmit=async e=>{e.preventDefault();const b=e.target.querySelector('button');b.disabled=true;try{
 const data={Token:token,Channel:channel};data[channel==='email'?'Email':'Phone']=e.target.elements.Contact.value;
 const r=await post('start',data);challenge=r.ID;$('#portal-sso').hidden=true;$('#phone-form').hidden=true;$('#code-form').hidden=false;$('#contact-back').hidden=false;
 $('#code-label').textContent=channel==='email'?'Код из письма':'Код из SMS';$('#code-form').elements.Code.value='';$('#code-form button').disabled=false;
 notice('Код отправлен: '+(r.MaskedContact||r.MaskedPhone));$('#expiry').textContent='Код действует до '+new Date(r.Expires*1000).toLocaleTimeString('ru-RU')+'.';$('#code-form').elements.Code.focus();
 }catch(err){notice(err.message,true);b.disabled=false;}};
$('#code-form').onsubmit=async e=>{e.preventDefault();const b=e.target.querySelector('button');b.disabled=true;try{const r=await post('verify',{ID:challenge,Code:e.target.elements.Code.value});$('#phone-form').hidden=true;$('#code-form').hidden=true;$('#contact-back').hidden=true;notice(r.ReconnectRequired?'Доступ разрешён. Переподключитесь к Wi-Fi для применения новой политики.':'Доступ разрешён; NAS подтвердил применение политики.');$('#expiry').textContent='Доступ действует до '+new Date(r.Expires*1000).toLocaleString('ru-RU');}catch(err){notice(err.message,true);b.disabled=false;}};
if(!token)notice('Откройте портал через гостевую сеть: нужен подписанный переход с NAS.',true);
else post('design',{Token:token}).then(d=>{
 design=d;const stage=$('#portal-stage');stage.dataset.position=d.Position;stage.dataset.align=d.ButtonAlign;stage.dataset.buttons=d.ButtonPosition;
 if(d.Background)stage.style.backgroundImage='url("'+d.Background+'")';$('#portal-title').textContent=d.Title;$('#portal-description').textContent=d.Description;
 $('#phone-form button').textContent=d.RequestLabel==='Получить SMS-код'?'Получить код':d.RequestLabel;$('#code-form button').textContent=d.ConfirmLabel;
 const names={yandex:'Яндекс',gosuslugi:'Госуслуги',google:'Google',apple:'Apple',vk:'VK',oidc:'Другой SSO-провайдер'},sso=$('#portal-sso');
 sso.replaceChildren();const title=document.createElement('p');title.textContent='Другие способы входа';sso.append(title);for(const id of d.SSOProviders||[]){if(!names[id])continue;const b=document.createElement('button');b.type='button';b.disabled=true;b.textContent=names[id]+' · недоступно';sso.append(b);}
 if(d.SSOPosition==='bottom')$('#login').insertBefore(sso,$('#expiry'));else $('#login').insertBefore(sso,$('#phone-form'));
 channel=d.LoginMethod==='email' ?'email':'sms';$('#channel-choice').hidden=d.LoginMethod!=='both';$('#phone-form').elements.Channel.value=channel;contactStep();
}).catch(e=>{notice(e.message,true);$('#phone-form').hidden=true;});
