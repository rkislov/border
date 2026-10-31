// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
'use strict';
(()=>{
 const nav=document.querySelector('#backups-nav');
 let poll=null,editing=false,exportEditing=false;
 const form=document.querySelector('#backup-schedule');
 const text=(parent,tag,value)=>{const node=document.createElement(tag);node.textContent=value;parent.append(node);return node;};
 const labels={pending:'В очереди',running:'Выполняется',succeeded:'Готово',failed:'Ошибка',pruned:'Удалена по сроку хранения',pruning:'Очистка'};
 const errors={interrupted:'Работа прервана перезапуском. Создайте новую копию.',expired:'Заявка старше 6 часов пропущена.',backup_failed:'Копия не прошла создание или проверку. Подробности — в журнале службы border-backup.',verification_failed:'Восстановление не подтверждено. Проверьте архив, ключ и журнал службы border-backup.'};
 async function api(path='',body){const r=await scopedFetch('/api/backups'+path,body?{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(body)}:undefined);if(r.status===404&&!body)return null;if(!r.ok)throw Error(await r.text());return r.json();}
 async function request(kind,source=''){await api('/jobs',{Kind:kind,SourceID:source,RequestID:crypto.randomUUID()});notice('Задание поставлено в очередь. Служба проверяет очередь каждую минуту.');await load();}
 async function load(){
  const v=await api();nav.hidden=!v;if(!v)return;
  filterNavigation();if(location.hash==='#backups'&&document.querySelector('#backups').hidden)activateView('backups');
  const schedule=v.Schedule;
  renderFileExports(v.Files);
  if(!editing){form.elements.Enabled.checked=schedule.Enabled;form.elements.Time.value=schedule.Time;form.elements.Timezone.value=schedule.Timezone;form.elements.Keep.value=schedule.Keep;}
  const status=document.querySelector('#backup-status');status.replaceChildren();
  text(status,'h2',v.Supported?'Резервные копии платформы':'PostgreSQL: механизм резервного копирования ещё не подключён');
  text(status,'p','Корневая база и все тенанты, конфигурация, сертификаты, ключи и бинарный файл. Архив зашифрован; ключ восстановления хранится отдельно.');
  const fresh=v.WorkerSeen&&Date.now()/1000-v.WorkerSeen<180;
  text(status,'p',v.WorkerSeen?'Последний запуск службы: '+date(v.WorkerSeen)+(fresh?' · служба доступна':' · проверьте системный таймер'):'Служба ещё не подключена. Администратору ОС нужно установить border-backup.timer и конфигурацию архива.');
  text(status,'p',schedule.Enabled?'Следующее окно: '+date(v.NextRun)+' · '+schedule.Timezone:'Автоматическое копирование отключено.');
  text(status,'p','Храним последних проверенных копий: '+schedule.Keep+'. Опоздание запуска — не более 6 часов. Проверка восстановления выполняется после каждой копии.');
  for(const el of form.elements)el.disabled=!v.Supported;
  document.querySelector('#backup-run').disabled=!v.Supported||!v.WorkerSeen||v.Jobs.some(j=>j.Kind==='backup'&&['pending','running'].includes(j.State));
  const list=document.querySelector('#backup-history');list.replaceChildren();
  if(!v.Jobs.length)text(list,'p','Резервных копий пока нет.');
  for(const j of v.Jobs){const row=document.createElement('article');row.className='draft-entry';list.append(row);
   text(row,'h3',(j.Kind==='verify'?'Проверка восстановления':'Резервная копия')+' · '+(labels[j.State]||j.State));
   text(row,'p',date(j.CreatedAt)+' · '+j.Actor+' · '+j.ID);
   if(j.SourceID)text(row,'p','Архив: '+j.SourceID);
   if(j.Report.VerifiedAt){const r=j.Report;const size=r.Bytes<1048576?(r.Bytes/1024).toFixed(1)+' КБ':(r.Bytes/1048576).toFixed(1)+' МБ';text(row,'p','Базы: '+r.Databases+' · тенанты: '+r.Tenants+' · файлы: '+r.Files+' · проверенные секреты: '+r.Secrets+' · '+size);}
   if(j.Kind==='backup'&&j.State==='succeeded'){text(row,'p',j.VerificationState==='ok'?'Восстановление проверено: '+date(j.VerifiedAt):'Последняя проверка восстановления завершилась ошибкой.');const button=text(row,'button','Проверить восстановление');button.type='button';button.disabled=v.Jobs.some(q=>q.SourceID===j.ID&&['pending','running'].includes(q.State));button.onclick=()=>request('verify',j.ID).catch(e=>notice(e.message,true));}
   if(j.Kind==='backup'&&j.State==='succeeded'&&j.VerificationState==='ok'){const b=text(row,'button','Подготовить скачивание');b.type='button';b.disabled=!v.Files.DownloadsReady;b.onclick=async()=>{try{await api('/downloads',{BackupID:j.ID});notice('Подготовка архива поставлена в очередь. Ссылка появится в очереди выгрузки.');await load();}catch(e){notice(e.message,true);}};}
   if(j.ErrorCode)text(row,'p',errors[j.ErrorCode]||j.ErrorCode);
  }
 }
 const exportForm=document.querySelector('#backup-file-settings');
 const exportErrors={destination_unavailable:'Папка недоступна: проверьте подключение и права.',archive_invalid:'Архив не прошёл проверку восстановления.',source_changed:'Локальный архив изменился.',source_unavailable:'Локальный архив недоступен.',destination_conflict:'В папке уже есть файл с другим содержимым. Он не перезаписан.',integrity_failed:'Контрольная сумма копии не совпала.',copy_failed:'Передача не завершена.',interrupted:'Передача прервана перезапуском.',target_changed:'Назначение изменено. Задание не перенаправляется автоматически.'};
 function renderFileExports(v){
  if(!exportEditing)exportForm.elements.Enabled.checked=v.Enabled;
  for(const el of exportForm.elements)el.disabled=!v.Target;
  document.querySelector('#backup-file-destination').textContent=v.Target?'Назначение: '+v.Label+'. Служба проверяет подключение сетевой папки перед передачей.':'Сетевая папка пока не подключена. '+(v.DownloadsReady?'Скачивание из панели доступно.':'Скачивание из панели ещё не подключено.');
  const list=document.querySelector('#backup-file-jobs');list.replaceChildren();
  if(!v.Jobs.length)text(list,'p','Заданий пока нет. Для скачивания выберите архив в истории ниже.');
  const states={pending:'В очереди',running:'Копирование и проверка',retrying:'Ожидает повторной попытки',succeeded:'Целостность подтверждена',failed:'Ошибка',paused:'Приостановлено',cancelled:'Отменено',expired:'Ссылка истекла'};
  for(const j of v.Jobs){const row=text(list,'article','');row.className='draft-entry';text(row,'h3',(j.Kind==='download'?'Скачивание':'Сетевая папка')+' · '+(states[j.State]||j.State));text(row,'p','Архив: '+j.BackupID+' · попыток: '+j.Attempts+' из 6');
   if(j.ErrorCode)text(row,'p',exportErrors[j.ErrorCode]||j.ErrorCode);
   if(j.State==='retrying')text(row,'p','Следующая попытка: '+date(j.NextAttempt));
   if(j.VerifiedAt)text(row,'p','Проверено: '+date(j.VerifiedAt)+' · '+(j.Bytes/1048576).toFixed(1)+' МБ · SHA-256: '+j.SHA256);
   if(j.Kind==='download'&&j.State==='succeeded'&&j.ExpiresAt>Date.now()/1000){text(row,'p','Ссылка действует до '+date(j.ExpiresAt)+'. Для восстановления нужен отдельный ключ age.');for(const [label,suffix] of [['Скачать архив',''],['Скачать SHA-256','?checksum=1']]){const a=text(row,'a',label);a.href=basePath+'/api/backups/downloads/'+encodeURIComponent(j.ID)+suffix;a.setAttribute('download','');a.className='backup-download-link';}}
   if(['failed','retrying','paused','cancelled','expired'].includes(j.State)||(j.Kind==='download'&&j.State==='succeeded')){const b=text(row,'button','Подготовить повторно');b.type='button';b.onclick=()=>fileAction(j.ID,'retry');}
   if(['pending','running','retrying','failed','paused'].includes(j.State)){const b=text(row,'button','Отменить');b.type='button';b.onclick=()=>{if(confirm('Отменить задание? После отмены сетевой выгрузки локальная копия снова подчиняется обычному сроку хранения. Уже записанный файл может остаться в сетевой папке.'))fileAction(j.ID,'cancel');};}
  }
 }
 async function fileAction(ID,Action){try{await api('/file-jobs/action',{ID,Action});await load();}catch(e){notice(e.message,true);}}
 exportForm.addEventListener('input',()=>{exportEditing=true;});
 exportForm.onsubmit=async e=>{e.preventDefault();try{await api('/file-export',{Enabled:exportForm.elements.Enabled.checked});exportEditing=false;notice('Настройки выгрузки сохранены');await load();}catch(e){notice(e.message,true);}};
 form.addEventListener('input',()=>{editing=true;});
 form.onsubmit=async e=>{e.preventDefault();try{await api('/schedule',{Enabled:form.elements.Enabled.checked,Time:form.elements.Time.value,Timezone:form.elements.Timezone.value,Keep:Number(form.elements.Keep.value)});editing=false;notice('Расписание сохранено');await load();}catch(e){notice(e.message,true);}};
 document.querySelector('#backup-run').onclick=()=>request('backup').catch(e=>notice(e.message,true));
 document.querySelector('#backup-refresh').onclick=()=>load().catch(e=>notice(e.message,true));
 function active(){clearInterval(poll);if(location.hash==='#backups'){load().catch(e=>notice(e.message,true));poll=setInterval(()=>{if(location.hash!=='#backups'){clearInterval(poll);return;}if(!document.hidden)load().catch(()=>{});},10000);}}
 nav.addEventListener('click',active);
 window.addEventListener('hashchange',active);
 api().then(v=>{nav.hidden=!v;filterNavigation();active();}).catch(()=>{});
})();
