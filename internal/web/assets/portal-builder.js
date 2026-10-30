'use strict';
(()=>{
 const form=document.querySelector('#portal-builder'),scope=form.elements.Scope,preview=document.querySelector('#portal-preview');let current;
 const providers={yandex:'Яндекс',gosuslugi:'Госуслуги',google:'Google',apple:'Apple',vk:'VK',oidc:'Другой SSO-провайдер'};
 const sso=document.createElement('div');sso.className='portal-sso';
 const fields=['SSOPosition','LoginMethod','Title','Description','RequestLabel','ConfirmLabel','Position','ButtonAlign','ButtonPosition'];
 const status=document.querySelector('#portal-builder-status');
 const show=e=>{status.textContent=e instanceof Error?e.message:e;};
 async function request(path,options){const r=await scopedFetch(path,options);if(!r.ok)throw new Error(await r.text());return r;}
 function render(){
  preview.dataset.position=form.elements.Position.value;
  preview.dataset.align=form.elements.ButtonAlign.value;
  preview.dataset.buttons=form.elements.ButtonPosition.value;
  preview.style.backgroundImage=current?.Background?'url("'+current.Background+'")':'none';
  for(const key of ['Title','Description','RequestLabel','ConfirmLabel'])preview.querySelector('[data-text="'+key+'"]').textContent=form.elements[key].value;
  const forms=preview.querySelectorAll('.portal-form');forms[0].hidden=form.elements.PreviewStep.value==='code';forms[1].hidden=form.elements.PreviewStep.value!=='code';
  const label=forms[0].querySelector('label');label.firstChild.textContent=form.elements.LoginMethod.value==='email'?'Электронная почта':'Номер телефона';forms[0].querySelector('input').placeholder=form.elements.LoginMethod.value==='email'?'user@example.org':'+79991234567';forms[1].querySelector('label').firstChild.textContent='Код подтверждения';
  sso.replaceChildren();const heading=document.createElement('p');heading.textContent='Другие способы входа';sso.append(heading);for(const [id,name] of Object.entries(providers)){if(form.elements['SSO_'+id].checked){const b=document.createElement('button');b.type='button';b.disabled=true;b.textContent=name+' · недоступно';sso.append(b);}}
  sso.hidden=!form.elements.SSOEnabled.checked||form.elements.PreviewStep.value==='code';const card=preview.querySelector('.portal-card');if(form.elements.SSOPosition.value==='top')card.insertBefore(sso,forms[0]);else card.append(sso);
  preview.classList.toggle('mobile',form.elements.Mobile.checked);
  status.textContent=form.elements.Custom.checked?'Собственное оформление. Предпросмотр не отправляет SMS.':'Наследование включено. Ниже показан сохранённый макет этой области; он не применяется.';
 }
 async function loadDesign(){const selected=scope.value;const d=await(await request('/api/portal-design?scope='+encodeURIComponent(selected))).json();if(scope.value!==selected)return;current=d;for(const f of fields)form.elements[f].value=d[f];form.elements.Custom.checked=d.Custom;form.elements.SSOEnabled.checked=!!d.SSOEnabled;for(const id of Object.keys(providers))form.elements["SSO_"+id].checked=(d.SSOProviders||[]).includes(id);render();}
 async function init(){const [model,state]=await Promise.all([request('/api/access-model').then(r=>r.json()),request('/api/state').then(r=>r.json())]);scope.replaceChildren(new Option('Тенант — по умолчанию','tenant'));for(const d of model.Domains)scope.add(new Option('Домен · '+d.Name,'domain:'+d.ID));for(const n of state.nas)scope.add(new Option('NAS · '+n.Name+' · '+n.Address,'nas:'+n.Address));await loadDesign();}
 document.querySelector('[data-view="portal-builder-view"]').addEventListener('click',()=>init().catch(show));
 scope.onchange=()=>loadDesign().catch(show);form.oninput=e=>{if(e.target!==scope)render();};
 form.onsubmit=async e=>{e.preventDefault();try{const d={Custom:form.elements.Custom.checked,SSOEnabled:form.elements.SSOEnabled.checked,SSOProviders:Object.keys(providers).filter(id=>form.elements["SSO_"+id].checked)};for(const f of fields)d[f]=form.elements[f].value;await request('/api/portal-design?scope='+encodeURIComponent(scope.value),{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(d)});show('Оформление сохранено');}catch(e){show(e);}};
 async function upload(body){await request('/api/portal-design/background?scope='+encodeURIComponent(scope.value),{method:'POST',headers:{'X-CSRF-Token':csrf,'Content-Type':'application/octet-stream'},body});const d=await(await request('/api/portal-design?scope='+encodeURIComponent(scope.value))).json();current.Background=d.Background;render();}
 form.elements.BackgroundFile.onchange=async e=>{try{const file=e.target.files[0];if(!file)return;if(file.size>2*1024*1024)throw Error('Максимальный размер — 2 МиБ');await upload(file);}catch(e){show(e);}finally{form.elements.BackgroundFile.value='';}};
 document.querySelector('#portal-background-remove').onclick=()=>upload(new Uint8Array()).catch(show);
 // Drop the card into one of nine responsive grid positions; keyboard users
 // have the equivalent position select, so no pixel coordinates are persisted.
 if(location.hash==="#portal-builder-view")init().catch(show);
 const card=preview.querySelector('.portal-card');card.draggable=true;card.ondragstart=e=>e.dataTransfer.setData('text/plain','border-portal-card');preview.ondragover=e=>e.preventDefault();preview.ondrop=e=>{e.preventDefault();if(e.dataTransfer.getData('text/plain')!=='border-portal-card')return;const r=preview.getBoundingClientRect(),x=Math.max(0,Math.min(2,Math.floor((e.clientX-r.left)/r.width*3))),y=Math.max(0,Math.min(2,Math.floor((e.clientY-r.top)/r.height*3)));form.elements.Position.value=[['top-left','top','top-right'],['left','center','right'],['bottom-left','bottom','bottom-right']][y][x];render();};
})();
