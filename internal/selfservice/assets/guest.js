const basePath=(location.pathname.match(/^\/(?:t|portal)\/[a-z][a-z0-9-]{0,31}(?=\/)/)||[''])[0];
const scopedFetch=(path,options)=>fetch(basePath+path,options);
'use strict';
const $=s=>document.querySelector(s),token=new URLSearchParams(location.search).get('token')||'';
history.replaceState(null,'',basePath+'/guest');let challenge='',design,channel='sms';
function notice(text,error=false){$('#notice').textContent=text;$('#notice').className=error?'error':'';$('#notice').hidden=false;}
async function post(path,data){const r=await scopedFetch('/api/guest/'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});if(!r.ok)throw new Error(await r.text());return r.json();}
function contactStep(){
 $('#method-choice').hidden=true;$('#method-back').hidden=false;
 challenge='';$('#code-form').hidden=true;$('#contact-back').hidden=true;$('#phone-form').hidden=false;$('#expiry').textContent='';$('#notice').hidden=true;
 const input=$('#phone-form').elements.Contact;input.type=channel==='email'?'email':'tel';input.autocomplete=channel==='email'?'email':'tel';input.placeholder=channel==='email'?'user@example.org':'+79991234567';input.value='';
 $('#contact-label').textContent=channel==='email'?'Электронная почта':'Номер телефона';$('#phone-form button').disabled=false;input.focus();
}
function methodStep(){
 challenge='';$('#phone-form').hidden=true;$('#code-form').hidden=true;$('#contact-back').hidden=true;$('#method-back').hidden=true;$('#method-choice').hidden=false;$('#notice').hidden=true;$('#expiry').textContent='';
 const first=$('#method-choice button');if(first)first.focus();else notice('Сейчас нет доступных способов входа. Обратитесь к администратору сети.',true);
}
$('#method-back').onclick=methodStep;
$('#contact-back').onclick=contactStep;
$('#phone-form').onsubmit=async e=>{e.preventDefault();const b=e.target.querySelector('button');b.disabled=true;try{
 const data={Token:token,Channel:channel};data[channel==='email'?'Email':'Phone']=e.target.elements.Contact.value;
 const r=await post('start',data);challenge=r.ID;$('#method-choice').hidden=true;$('#method-back').hidden=true;$('#phone-form').hidden=true;$('#code-form').hidden=false;$('#contact-back').hidden=false;
 $('#code-label').textContent=channel==='email'?'Код из письма':'Код из SMS';$('#code-form').elements.Code.value='';$('#code-form button').disabled=false;
 notice('Код отправлен: '+(r.MaskedContact||r.MaskedPhone));$('#expiry').textContent='Код действует до '+new Date(r.Expires*1000).toLocaleTimeString('ru-RU')+'.';$('#code-form').elements.Code.focus();
 }catch(err){notice(err.message,true);b.disabled=false;}};
$('#code-form').onsubmit=async e=>{e.preventDefault();const b=e.target.querySelector('button');b.disabled=true;try{const r=await post('verify',{ID:challenge,Code:e.target.elements.Code.value});$('#phone-form').hidden=true;$('#code-form').hidden=true;$('#contact-back').hidden=true;notice(r.ReconnectRequired?'Доступ разрешён. Переподключитесь к Wi-Fi для применения новой политики.':'Доступ разрешён; NAS подтвердил применение политики.');$('#expiry').textContent='Доступ действует до '+new Date(r.Expires*1000).toLocaleString('ru-RU');}catch(err){notice(err.message,true);b.disabled=false;}};
if(!token)notice('Откройте портал через гостевую сеть: нужен подписанный переход с NAS.',true);
else post('design',{Token:token}).then(d=>{
 design=d;const stage=$('#portal-stage');stage.dataset.position=d.Position;stage.dataset.align=d.ButtonAlign;stage.dataset.buttons=d.ButtonPosition;
 if(d.Background)stage.style.backgroundImage='url("'+d.Background+'")';$('#portal-title').textContent=d.Title;$('#portal-description').textContent=d.Description;
 $('#phone-form button').textContent=d.RequestLabel==='Получить SMS-код'?'Получить код':d.RequestLabel;$('#code-form button').textContent=d.ConfirmLabel;
 const names={sms:'SMS',email:'Электронная почта'},chooser=$('#method-choice');chooser.replaceChildren();
 for(const method of d.Methods||[]){if(!names[method])continue;const b=document.createElement('button');b.type='button';b.textContent=names[method];b.onclick=()=>{channel=method;contactStep();};chooser.append(b);}
 const sso=document.createDocumentFragment();
 for(const provider of d.OIDC||[]){const b=document.createElement('button');b.type='button';b.textContent=provider.Name;b.onclick=async()=>{b.disabled=true;try{const result=await post('oidc/start',{Token:token,Provider:provider.ID});const target=new URL(result.URL);if(target.protocol!=='https:')throw Error('Недопустимый адрес провайдера');location.assign(target.href);}catch(e){notice(e.message,true);b.disabled=false;}};sso.append(b);}
 if(d.SSOPosition==='top')chooser.prepend(sso);else chooser.append(sso);
 methodStep();
}).catch(e=>{notice(e.message,true);$('#phone-form').hidden=true;});
