'use strict';
let policyDraftCache=[], draftChoiceModel=null;
const policyKindNames={authentication:'Авторизация',access:'Доступ',rules:'Правила доступа',group:'Группа',segment:'Сегмент',mapping:'Сопоставление VLAN','nas-policies':'Набор политик NAS','nas-assignment':'Одиночная политика NAS'};
const selectedDrafts=new Set();
const draftKey=d=>d.Kind+'/'+d.PolicyID;
const draftRef=d=>({Kind:d.Kind,PolicyID:d.PolicyID,Revision:d.Revision});
const payloadID=(kind,p)=>kind==='mapping'?(p.NAS?'nas/'+p.NAS:'location/'+p.LocationID)+'/'+p.SegmentID:p.ID||p.PolicyID||p.NAS;
async function draftAPI(path,data){const r=await scopedFetch('/api/policy-drafts'+path,{method:data?'POST':'GET',headers:data?{'Content-Type':'application/json','X-CSRF-Token':csrf}:{},body:data?JSON.stringify(data):undefined});if(!r.ok)throw new Error(await r.text());return r.status===204?null:r.json();}
function draftButton(text,fn){const b=document.createElement('button');b.type='button';b.textContent=text;b.onclick=async()=>{b.disabled=true;try{await fn();}catch(e){notice(e.message,true);}finally{b.disabled=false;}};return b;}
function draftText(parent,tag,text){const el=document.createElement(tag);el.textContent=text;parent.append(el);return el;}
function applyDraftChoices(){
 if(!draftChoiceModel)return;
 for(const [kind,field,selector] of [['authentication','Authentication','.authentication-select'],['access','Access','.access-select,.rule-policy-select'],['segment','Segments','.segment-select']]){
  const items=new Map(draftChoiceModel[field].map(v=>[v.ID,v]));for(const d of policyDraftCache.filter(d=>d.Kind===kind))items.set(d.PolicyID,{...d.Payload,Name:d.Payload.Name+' (черновик)'});selectItems(selector,[...items.values()]);
 }
 const sel=$('#assignment-nas'),old=sel.value;sel.replaceChildren(new Option('Выберите NAS',''));for(const n of state?.nas||[])sel.add(new Option(n.Name+' · '+n.Address,n.Address));sel.value=old;
}
async function loadPolicyDrafts(){
 const v=await draftAPI('');policyDraftCache=v.Drafts;const keys=new Set(v.Drafts.map(draftKey));for(const key of selectedDrafts)if(!keys.has(key))selectedDrafts.delete(key);
 const holder=$('#policy-draft-list');holder.replaceChildren();
 if(!v.Drafts.length)draftText(holder,'p','Черновиков пока нет. Сохраните изменения в редакторе.');
 for(const d of v.Drafts){
  const row=document.createElement('div');row.className='draft-entry';const label=document.createElement('label'),check=document.createElement('input');check.type='checkbox';check.checked=selectedDrafts.has(draftKey(d));check.onchange=()=>{if(check.checked)selectedDrafts.add(draftKey(d));else selectedDrafts.delete(draftKey(d));$('#policy-impact').hidden=true;};label.append(check,document.createTextNode(' В пакет: '+policyKindNames[d.Kind]+' · '+d.PolicyID));row.append(label);draftText(row,'p','Редакция '+d.Revision+' · '+d.Actor+' · '+date(d.UpdatedAt));
  row.append(draftButton('Оценить отдельно',()=>showPolicyBatch([d])),draftButton('Редактировать',()=>editPolicyDraft(d)),draftButton('Удалить черновик',async()=>{if(!confirm('Удалить черновик '+d.PolicyID+'? Рабочая конфигурация сохранится.'))return;await draftAPI('/discard',draftRef(d));$('#policy-impact').hidden=true;await loadPolicyDrafts();}));holder.append(row);
 }
 const history=$('#policy-release-list');history.replaceChildren();if(!v.Releases.length)draftText(history,'p','Публикаций пока нет.');const batches=new Map();
 for(const r of v.Releases){const key=r.BatchID||r.ID;if(!batches.has(key))batches.set(key,[]);batches.get(key).push(r);}
 for(const [key,items] of batches){
  const row=document.createElement('div');row.className='draft-entry';draftText(row,'h3',items[0].BatchID?'Пакет '+key.slice(0,8):'Публикация');draftText(row,'p',date(items[0].CreatedAt)+' · '+items[0].Actor);
  for(const r of items){const details=document.createElement('details');draftText(details,'summary',policyKindNames[r.Kind]+' · '+r.PolicyID);draftText(details,'pre',JSON.stringify(r.After,null,2));row.append(details);}
  row.append(draftButton('Подготовить откат',async()=>{await draftAPI(items[0].BatchID?'/batch/rollback':'/rollback',items[0].BatchID?{BatchID:key}:{ReleaseID:key});$('#policy-impact').hidden=true;await loadPolicyDrafts();notice('Черновики отката созданы. Выберите их в пакет и оцените влияние.');}));history.append(row);
 }
 applyDraftChoices();
}
async function savePolicyDraft(kind,payload){try{const id=payloadID(kind,payload),existing=policyDraftCache.find(d=>d.Kind===kind&&d.PolicyID===id);await draftAPI('',{Kind:kind,PolicyID:id,Revision:existing?.Revision||0,Payload:payload});$('#policy-impact').hidden=true;await loadPolicyDrafts();notice('Черновик сохранён. Связанные изменения можно опубликовать одним пакетом.');return true;}catch(e){notice(e.message,true);return false;}}
function editPolicyDraft(d){
 const p=structuredClone(d.Payload);
 if(d.Kind==='rules'){activateView('access',true);$('#rule-policy').value=d.PolicyID;ruleDraft=p;rulesDirty=true;renderRuleDraft();return;}
 if(d.Kind==='nas-policies'){activateView('nas',true);$('#bindings-nas').value=p.NAS;bindingsDraft=p;bindingsDirty=true;renderBindings();return;}
 const forms={authentication:['authentication','authentication-form'],access:['access','access-form'],group:['users','user-group-form'],segment:['locations','segment-form'],mapping:['locations','mapping-form'],'nas-assignment':['nas','nas-assignment-form']};const [view,form]=forms[d.Kind];activateView(view,true);fillForm('#'+form,p);
}
function renderDraftDiff(h,d){
 const details=document.createElement('details');details.open=true;draftText(details,'summary',policyKindNames[d.Kind]+' · '+d.PolicyID+' · редакция '+d.Revision);
 const labels={Name:'Название',Enabled:'Включено',Source:'Источник',DomainID:'Домен',Steps:'Проверки',AuthenticationID:'Авторизация',Mode:'Назначение',SegmentID:'Сегмент',LocationID:'Расположение',VLAN:'VLAN',AccessPolicyID:'Политика доступа',SessionSeconds:'Срок сессии, сек.',Subjects:'Личности',Members:'Участники',Rules:'Правила',Bindings:'Привязки'};
 for(const key of Object.keys(d.Payload)){if(['ID','PolicyID','Version','NAS'].includes(key))continue;const before=d.Base?.[key],after=d.Payload[key];if(JSON.stringify(before)!==JSON.stringify(after))draftText(details,'p',(labels[key]||key)+': '+(before===undefined?'—':JSON.stringify(before))+' → '+JSON.stringify(after));}h.append(details);
}
async function showPolicyBatch(ds){
 const refs=ds.map(draftRef),v=await draftAPI('/batch/impact',{Drafts:refs}),h=$('#policy-impact');h.hidden=false;h.replaceChildren();draftText(h,'h2','Оценка пакета · '+refs.length+' изменений');
 draftText(h,'p','NAS: '+v.Devices.length+' · связанные активные/зависшие сессии: '+v.Sessions.length+' · без привязки: '+v.UnlinkedSessions.length+'.');
 draftText(h,'p','Проверяются зависимости итоговой конфигурации. Снимок сессий может измениться к публикации; работа LDAP и фактический Disconnect на оборудовании здесь не проверяются.');
 for(const error of v.Errors)draftText(h,'p','Публикация заблокирована: '+error);
 draftText(h,'p',v.Devices.join(', ')||'Затронутых NAS нет');for(const d of v.Drafts)renderDraftDiff(h,d);
 for(const [label,items] of [['Потребуют повторного входа',v.Sessions],['Не отключаются автоматически: нет привязки',v.UnlinkedSessions]]){draftText(h,'h3',label);for(const s of items)draftText(h,'p',s.NAS+' · '+s.ID+' · '+s.Username+' · '+s.Status);}
 if(!v.Errors.length)h.append(draftButton('Опубликовать пакет',async()=>{if(!confirm('Опубликовать весь пакет? Затронутые разрешения будут отозваны.'))return;await draftAPI('/batch/publish',{Drafts:refs});h.hidden=true;selectedDrafts.clear();await load();notice('Пакет опубликован целиком. Ход отзыва доступен в разделе сессий.');}));
}
$('#drafts-refresh').onclick=()=>{ $('#policy-impact').hidden=true;loadPolicyDrafts().catch(e=>notice(e.message,true));};
$('#drafts-select-all').onclick=()=>{for(const d of policyDraftCache)selectedDrafts.add(draftKey(d));loadPolicyDrafts().catch(e=>notice(e.message,true));};
$('#drafts-assess').onclick=()=>{const ds=policyDraftCache.filter(d=>selectedDrafts.has(draftKey(d)));if(!ds.length){notice('Выберите черновики для пакета',true);return;}showPolicyBatch(ds).catch(e=>notice(e.message,true));};
for(const id of ['authentication-form','access-form','user-group-form','segment-form','mapping-form']){const f=$('#'+id);f.querySelector('button[type="submit"],button.primary').textContent='Сохранить черновик';const p=document.createElement('p');p.textContent='Сохранение создаёт черновик. Применение — в разделе «Черновики и публикации».';f.prepend(p);}
$('#save-rules').textContent='Сохранить черновик правил';$('#bindings-save').textContent='Сохранить черновик привязок';
$('#assignment-nas').onchange=()=>{const nas=$('#assignment-nas').value,d=policyDraftCache.find(d=>d.Kind==='nas-assignment'&&d.PolicyID===nas);$('#nas-assignment-form').elements.AccessPolicyID.value=d?.Payload.AccessPolicyID??state?.nas.find(n=>n.Address===nas)?.AccessPolicyID??'';};
$('#nas-assignment-form').onsubmit=async e=>{e.preventDefault();await savePolicyDraft('nas-assignment',Object.fromEntries(new FormData(e.target)));};
