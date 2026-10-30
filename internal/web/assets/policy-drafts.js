'use strict';
let policyDraftCache=[], draftChoiceModel=null, reviewSettings={Required:false,Revision:0}, policyReviews=[], reviewUsername="";
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
  const items=new Map(draftChoiceModel[field].map(v=>[v.ID,v]));for(const d of policyDraftCache.filter(d=>d.Kind===kind)){if(d.Payload===null){items.delete(d.PolicyID);continue;}items.set(d.PolicyID,{...d.Payload,Name:d.Payload.Name+' (черновик)'});}selectItems(selector,[...items.values()]);
 }
 const sel=$('#assignment-nas'),old=sel.value;sel.replaceChildren(new Option('Выберите NAS',''));for(const n of state?.nas||[])sel.add(new Option(n.Name+' · '+n.Address,n.Address));sel.value=old;
}
async function loadPolicyDrafts(){
 const v=await draftAPI('');updateReviewState(v);renderReviews();policyDraftCache=v.Drafts;const keys=new Set(v.Drafts.map(draftKey));for(const key of selectedDrafts)if(!keys.has(key))selectedDrafts.delete(key);
 const holder=$('#policy-draft-list');holder.replaceChildren();
 if(!v.Drafts.length)draftText(holder,'p','Черновиков пока нет. Сохраните изменения в редакторе.');
 for(const d of v.Drafts){
  const row=document.createElement('div');row.className='draft-entry';const label=document.createElement('label'),check=document.createElement('input');check.type='checkbox';check.checked=selectedDrafts.has(draftKey(d));check.onchange=()=>{if(check.checked)selectedDrafts.add(draftKey(d));else selectedDrafts.delete(draftKey(d));$('#policy-impact').hidden=true;};label.append(check,document.createTextNode(' В пакет: '+policyKindNames[d.Kind]+' · '+d.PolicyID));row.append(label);draftText(row,'p',(d.Payload===null?'УДАЛЕНИЕ · ':'Изменение · ')+'Редакция '+d.Revision+' · '+d.Actor+' · '+date(d.UpdatedAt));
  row.append(draftButton('Оценить отдельно',()=>showPolicyBatch([d])),...(d.Payload===null?[]:[draftButton('Редактировать',()=>editPolicyDraft(d))]),draftButton('Удалить черновик',async()=>{if(!confirm('Удалить черновик '+d.PolicyID+'? Рабочая конфигурация сохранится.'))return;await draftAPI('/discard',draftRef(d));$('#policy-impact').hidden=true;await loadPolicyDrafts();}));holder.append(row);
 }
 const history=$('#policy-release-list');history.replaceChildren();if(!v.Releases.length)draftText(history,'p','Публикаций пока нет.');const batches=new Map();
 for(const r of v.Releases){const key=r.BatchID||r.ID;if(!batches.has(key))batches.set(key,[]);batches.get(key).push(r);}
 for(const [key,items] of batches){
  const row=document.createElement('div');row.className='draft-entry';draftText(row,'h3',items[0].BatchID?'Пакет '+key.slice(0,8):'Публикация');draftText(row,'p',date(items[0].CreatedAt)+' · '+items[0].Actor);
  for(const r of items){const details=document.createElement('details');draftText(details,'summary',policyKindNames[r.Kind]+' · '+r.PolicyID);draftText(details,'pre',r.After===null?'Объект удалён':JSON.stringify(r.After,null,2));row.append(details);}
  row.append(draftButton('Подготовить откат',async()=>{await draftAPI(items[0].BatchID?'/batch/rollback':'/rollback',items[0].BatchID?{BatchID:key}:{ReleaseID:key});$('#policy-impact').hidden=true;await loadPolicyDrafts();notice('Черновики отката созданы. Выберите их в пакет и оцените влияние.');}));history.append(row);
 }
 applyDraftChoices();renderDeletionChoices();
}
async function savePolicyDraft(kind,payload){try{const id=payloadID(kind,payload),existing=policyDraftCache.find(d=>d.Kind===kind&&d.PolicyID===id);await draftAPI('',{Kind:kind,PolicyID:id,Revision:existing?.Revision||0,Payload:payload});$('#policy-impact').hidden=true;await loadPolicyDrafts();notice('Черновик сохранён. Связанные изменения можно опубликовать одним пакетом.');return true;}catch(e){notice(e.message,true);return false;}}
function editPolicyDraft(d){
 if(d.Payload===null){notice('Это черновик удаления. Его можно исключить из пакета или удалить.',true);return;}const p=structuredClone(d.Payload);
 if(d.Kind==='rules'){activateView('access',true);$('#rule-policy').value=d.PolicyID;ruleDraft=p;rulesDirty=true;renderRuleDraft();return;}
 if(d.Kind==='nas-policies'){activateView('nas',true);$('#bindings-nas').value=p.NAS;bindingsDraft=p;bindingsDirty=true;renderBindings();return;}
 const forms={authentication:['authentication','authentication-form'],access:['access','access-form'],group:['users','user-group-form'],segment:['locations','segment-form'],mapping:['locations','mapping-form'],'nas-assignment':['nas','nas-assignment-form']};const [view,form]=forms[d.Kind];activateView(view,true);fillForm('#'+form,p);
}
function renderDraftDiff(h,d){
 const details=document.createElement('details');details.open=true;draftText(details,'summary',policyKindNames[d.Kind]+' · '+d.PolicyID+' · редакция '+d.Revision);
 if(d.Payload===null){draftText(details,'p','Удаление объекта при публикации. Сохранённая версия останется в истории для отката.');draftText(details,'pre',JSON.stringify(d.Base,null,2));h.append(details);return;}
 const labels={Name:'Название',Enabled:'Включено',Source:'Источник',DomainID:'Домен',Steps:'Проверки',AuthenticationID:'Авторизация',Mode:'Назначение',SegmentID:'Сегмент',LocationID:'Расположение',VLAN:'VLAN',AccessPolicyID:'Политика доступа',SessionSeconds:'Срок сессии, сек.',Subjects:'Личности',Members:'Участники',Rules:'Правила',Bindings:'Привязки'};
 for(const key of Object.keys(d.Payload)){if(['ID','PolicyID','Version','NAS'].includes(key))continue;const before=d.Base?.[key],after=d.Payload[key];if(JSON.stringify(before)!==JSON.stringify(after))draftText(details,'p',(labels[key]||key)+': '+(before===undefined?'—':JSON.stringify(before))+' → '+JSON.stringify(after));}h.append(details);
}
async function showPolicyBatch(ds,selectedReview=null){
 updateReviewState(await draftAPI(''));
 const refs=ds.map(draftRef),v=await draftAPI('/batch/impact',{Drafts:refs}),h=$('#policy-impact');h.hidden=false;h.replaceChildren();draftText(h,'h2','Оценка пакета · '+refs.length+' изменений');
 draftText(h,'p','NAS: '+v.Devices.length+' · связанные активные/зависшие сессии: '+v.Sessions.length+' · без привязки: '+v.UnlinkedSessions.length+'.');
 draftText(h,'p','Проверяются зависимости итоговой конфигурации. Снимок сессий может измениться к публикации; работа LDAP и фактический Disconnect на оборудовании здесь не проверяются.');
 for(const error of v.Errors)draftText(h,'p','Публикация заблокирована: '+error);
 draftText(h,'p',v.Devices.join(', ')||'Затронутых NAS нет');for(const d of v.Drafts)renderDraftDiff(h,d);
 for(const [label,items] of [['Потребуют повторного входа',v.Sessions],['Не отключаются автоматически: нет привязки',v.UnlinkedSessions]]){draftText(h,'h3',label);for(const s of items)draftText(h,'p',s.NAS+' · '+s.ID+' · '+s.Username+' · '+s.Status);}
 renderReviewActions(h,refs,v,selectedReview);

}
$('#drafts-refresh').onclick=()=>{ $('#policy-impact').hidden=true;loadPolicyDrafts().catch(e=>notice(e.message,true));};
$('#drafts-select-all').onclick=()=>{for(const d of policyDraftCache)selectedDrafts.add(draftKey(d));loadPolicyDrafts().catch(e=>notice(e.message,true));};
$('#drafts-assess').onclick=()=>{const ds=policyDraftCache.filter(d=>selectedDrafts.has(draftKey(d)));if(!ds.length){notice('Выберите черновики для пакета',true);return;}showPolicyBatch(ds).catch(e=>notice(e.message,true));};
for(const id of ['authentication-form','access-form','user-group-form','segment-form','mapping-form']){const f=$('#'+id);f.querySelector('button[type="submit"],button.primary').textContent='Сохранить черновик';const p=document.createElement('p');p.textContent='Сохранение создаёт черновик. Применение — в разделе «Черновики и публикации».';f.prepend(p);}
$('#save-rules').textContent='Сохранить черновик правил';$('#bindings-save').textContent='Сохранить черновик привязок';
$('#assignment-nas').onchange=()=>{const nas=$('#assignment-nas').value,d=policyDraftCache.find(d=>d.Kind==='nas-assignment'&&d.PolicyID===nas);$('#nas-assignment-form').elements.AccessPolicyID.value=d?.Payload?.AccessPolicyID??state?.nas.find(n=>n.Address===nas)?.AccessPolicyID??'';};
$('#nas-assignment-form').onsubmit=async e=>{e.preventDefault();await savePolicyDraft('nas-assignment',Object.fromEntries(new FormData(e.target)));};

function renderDeletionChoices(){
 if(!draftChoiceModel)return;
 const kind=$('#deletion-kind').value,sel=$('#deletion-object'),old=sel.value,m=draftChoiceModel;
 let items=[];
 if(kind==='authentication')items=m.Authentication.map(x=>[x.ID,x.Name]);
 if(kind==='access')items=m.Access.map(x=>[x.ID,x.Name]);
 if(kind==='rules')items=m.RuleSets.filter(x=>x.Version>0).map(x=>[x.PolicyID,x.PolicyID]);
 if(kind==='group')items=m.Groups.map(x=>[x.ID,x.Name]);
 if(kind==='segment')items=m.Segments.map(x=>[x.ID,x.Name]);
 if(kind==='mapping')items=m.Mappings.map(x=>[payloadID('mapping',x),payloadID('mapping',x)+' · VLAN '+x.VLAN]);
 if(kind==='nas-policies')items=(state?.nas||[]).map(x=>[x.Address,x.Name]);
 if(kind==='nas-assignment')items=(state?.nas||[]).filter(x=>x.AccessPolicyID).map(x=>[x.Address,x.Name+' · '+x.AccessPolicyID]);
 sel.replaceChildren(new Option('Выберите объект',''));for(const [id,name] of items)sel.add(new Option(name+' · '+id,id));if([...sel.options].some(x=>x.value===old))sel.value=old;
}
$('#deletion-kind').onchange=renderDeletionChoices;
$('#deletion-form').onsubmit=async e=>{e.preventDefault();const kind=$('#deletion-kind').value,id=$('#deletion-object').value,d=policyDraftCache.find(x=>x.Kind===kind&&x.PolicyID===id);if(d&&!confirm('Заменить существующий черновик '+id+' на удаление?'))return;try{await draftAPI('',{Kind:kind,PolicyID:id,Revision:d?.Revision||0,Operation:'delete'});$('#policy-impact').hidden=true;await loadPolicyDrafts();notice('Черновик удаления создан. Объект действует до публикации пакета.');}catch(e){notice(e.message,true);}};

const reviewStateLabels={pending:'Ожидает проверки',approved:'Одобрен',rejected:'Отклонён',stale:'Согласование сброшено',published:'Опубликован'};
const reviewRefsKey=refs=>JSON.stringify(refs.map(r=>[r.Kind,r.PolicyID,r.Revision]).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b))));
let policySchedules=[];
function updateReviewState(v){policySchedules=v.Schedules||[];reviewSettings=v.ReviewSettings;policyReviews=v.Reviews;reviewUsername=v.Username;$('#review-required').checked=reviewSettings.Required;$('#review-mode-status').textContent=reviewSettings.Required?'Публикация требует одобрения второго администратора.':'Согласование выключено: администратор может публиковать самостоятельно.';}
function renderReviews(){const holder=$('#review-list');holder.replaceChildren();if(!policyReviews.length)draftText(holder,'p','Заявок на согласование пока нет.');for(const r of policyReviews){const row=document.createElement('div');row.className='draft-entry';draftText(row,'h3',(reviewStateLabels[r.State]||r.State)+' · '+r.ID.slice(0,8));draftText(row,'p','Отправил '+r.Requester+' · '+date(r.CreatedAt)+' · объектов: '+r.Drafts.length);if(r.RequestComment)draftText(row,'p','Комментарий автора: '+r.RequestComment);if(r.Reviewer)draftText(row,'p','Проверил '+r.Reviewer+(r.DecisionComment?' · '+r.DecisionComment:''));if(r.Reason)draftText(row,'p','Причина: '+reviewReason(r.Reason));if(r.BatchID)draftText(row,'p','Публикация: '+r.BatchID);row.append(draftButton('Открыть заявку',async()=>{const full=await draftAPI('/reviews/'+encodeURIComponent(r.ID));await showPolicyBatch(full.Drafts,full);}));renderScheduleControls(row,r);holder.append(row);}renderScheduleHistory(holder);}
function reviewReason(reason){return ({'draft changed':'Изменена редакция черновика','draft discarded':'Черновик удалён','draft published in another package':'Черновик опубликован в другом пакете','approval mode changed':'Изменён режим согласования','reviewer account changed':'Изменены права или учётная запись согласующего'})[reason]||reason;}
function reviewComment(h,text){const label=document.createElement('label');label.append(document.createTextNode(text));const input=document.createElement('textarea');input.maxLength=1000;input.rows=3;label.append(input);h.append(label);return input;}
function renderReviewActions(h,refs,impact,selectedReview){
 const key=reviewRefsKey(refs),active=policyReviews.find(r=>['pending','approved'].includes(r.State)&&reviewRefsKey(r.Drafts)===key),review=selectedReview?(policyReviews.find(r=>r.ID===selectedReview.ID)||selectedReview):active;
 if(review){draftText(h,'h3','Согласование: '+(reviewStateLabels[review.State]||review.State));draftText(h,'p','Отправил '+review.Requester+' · '+date(review.CreatedAt));if(review.RequestComment)draftText(h,'p',review.RequestComment);if(review.Reviewer)draftText(h,'p','Проверил '+review.Reviewer+' · '+review.DecisionComment);if(review.Reason)draftText(h,'p',reviewReason(review.Reason));}
 if(selectedReview&&impact.Errors.length){const history=document.createElement('details');draftText(history,'summary','Снимок изменений на момент отправки');for(const d of selectedReview.Snapshot||[])renderDraftDiff(history,d);h.append(history);}
 if(reviewSettings.Required&&review?.State==='pending'){
  if(review.Authors.includes(reviewUsername)){draftText(h,'p','Отправитель и авторы черновиков не могут согласовать свой пакет. Ожидается другой администратор.');}
  else {const comment=reviewComment(h,'Комментарий проверяющего (обязателен при отклонении)');const decide=async approve=>{if(!approve&&!comment.value.trim()){notice('Укажите причину отклонения',true);return;}await draftAPI('/reviews/decision',{ID:review.ID,Approve:approve,Comment:comment.value});await loadPolicyDrafts();await showPolicyBatch(refs);notice(approve?'Пакет одобрен. Изменение черновика сбросит одобрение.':'Пакет отклонён.');};if(!impact.Errors.length)h.append(draftButton('Одобрить пакет',()=>decide(true)));h.append(draftButton('Отклонить пакет',()=>decide(false)));}
 }
 if(!impact.Errors.length&&reviewSettings.Required&&!active){const comment=reviewComment(h,'Комментарий для согласующего');h.append(draftButton('Отправить на согласование',async()=>{await draftAPI('/reviews',{Drafts:refs,Comment:comment.value});await loadPolicyDrafts();await showPolicyBatch(refs);notice('Пакет отправлен другому администратору на проверку.');}));}
 if(!impact.Errors.length&&(!reviewSettings.Required||active?.State==='approved'))h.append(draftButton('Опубликовать пакет',async()=>{if(!confirm('Опубликовать весь пакет? Затронутые разрешения будут отозваны.'))return;await draftAPI('/batch/publish',{Drafts:refs});h.hidden=true;selectedDrafts.clear();await load();notice('Пакет опубликован целиком. Ход отзыва доступен в разделе сессий.');}));
}
$('#review-settings-form').onsubmit=async e=>{e.preventDefault();try{await draftAPI('/review-settings',{Required:$('#review-required').checked,Revision:reviewSettings.Revision});$('#policy-impact').hidden=true;await loadPolicyDrafts();notice('Режим согласования сохранён.');}catch(err){notice(err.message,true);}};

const scheduleLabels={pending:'Запланировано',published:'Опубликовано',blocked:'Заблокировано',cancelled:'Отменено'};
function scheduleReason(reason){const known={'approval: request is no longer approved':'Одобрение недействительно или пакет уже опубликован','approval: review mode is disabled':'Согласование выключено','approval: active administrator required':'Администратор заблокирован или лишён прав','approval: scheduling administrator account changed':'Изменена учётная запись автора расписания','approval: reviewer account changed; submit a new request':'Изменена учётная запись согласующего; требуется новая заявка','approval: second administrator approval required for this exact package':'Нет действующего одобрения точного состава пакета'};if(known[reason])return known[reason];if(reason.includes('changed'))return 'Черновики или рабочая конфигурация изменились. Выполните оценку пакета заново.';if(reason==='cancelled by administrator')return 'Отменено администратором';return reason;}
function renderScheduleControls(row,review){
 const pending=policySchedules.find(s=>s.ReviewID===review.ID&&s.State==='pending');
 if(pending){draftText(row,'p','Публикация запланирована на '+date(pending.DueAt)+' · '+pending.Actor);row.append(draftButton('Отменить расписание',async()=>{await draftAPI('/schedules/cancel',{ID:pending.ID});await loadPolicyDrafts();notice('Расписание отменено. Одобрение пакета сохранено.');}));return;}
 if(review.State!=='approved'||!reviewSettings.Required)return;
 const label=document.createElement('label');label.append(document.createTextNode('Дата и время публикации ('+Intl.DateTimeFormat().resolvedOptions().timeZone+')'));const input=document.createElement('input');input.type='datetime-local';label.append(input);row.append(label);
 row.append(draftButton('Запланировать публикацию',async()=>{const due=Math.floor(new Date(input.value).getTime()/1000);if(!Number.isFinite(due)||due<=Date.now()/1000){notice('Укажите будущее время публикации',true);return;}await draftAPI('/schedules',{ReviewID:review.ID,DueAt:due});await loadPolicyDrafts();notice('Расписание сохранено. Перед публикацией пакет будет проверен повторно.');}));
}
function renderScheduleHistory(holder){if(!policySchedules.length)return;draftText(holder,'h3','Расписание и результаты');draftText(holder,'p','Время показано в часовом поясе браузера. Проверка каждые 10 секунд; после простоя просроченные задания выполняются при запуске с повторной проверкой. Заблокированные задания не повторяются автоматически.');for(const job of policySchedules){const row=document.createElement('div');row.className='draft-entry';draftText(row,'h3',(scheduleLabels[job.State]||job.State)+' · '+date(job.DueAt));draftText(row,'p','Заявка '+job.ReviewID.slice(0,8)+' · запланировал '+job.Actor);if(job.Reason)draftText(row,'p','Причина: '+scheduleReason(job.Reason));if(job.BatchID)draftText(row,'p','Публикация: '+job.BatchID);holder.append(row);}}
