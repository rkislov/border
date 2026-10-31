'use strict';
function renderPublicationResult(holder, result, reload) {
  const labels = {in_progress:'Выполняется',attention:'Требует внимания',completed:'Завершено',pending:'Ожидает отзыва',sending:'Отправка запроса',retrying:'Ошибка — будет повтор',awaiting_stop:'NAS ответил ACK — ожидается Accounting-Stop',stopped:'Подтверждено Accounting-Stop',nas_on:'Завершено по Accounting-On',nas_off:'Завершено по Accounting-Off',adapter_confirmed:'Отключение проверено адаптером NAS',unlinked:'Нет разрешения — автоматический отзыв недоступен',superseded:'Новое поколение — завершение прежнего не подтверждено',missing:'Сессия отсутствует — завершение не подтверждено',timeout:'Истёк срок ожидания подтверждения',waiting_accounting:'Ожидается первое accounting-событие',accounting_timeout:'Accounting не получен в срок'};
  const section = document.createElement('section');
  section.className = 'publication-result';
  holder.append(section);
  draftText(section,'h3','Результат отзыва доступа · '+(labels[result.State]||result.State));
  draftText(section,'p','Статус относится к сессиям этого пакета. ACK подтверждает ответ NAS; завершение учитывается отдельно. Общий итог обновляется фоновым обработчиком.');
  section.append(draftButton('Обновить результат',reload));
  for (const s of result.Sessions) {
    const card=document.createElement('article');card.className='draft-entry';section.append(card);
    draftText(card,'h4',s.NAS+' / '+s.ID+' · '+s.Username);
    draftText(card,'p',labels[s.State]||s.State);
    draftText(card,'small','Поколение: '+s.Generation+' · политика: '+(s.PolicyID||'—'));
    if(s.Attempts) draftText(card,'p','Попыток: '+s.Attempts+' · последняя: '+date(s.LastAttempt));
    if(s.NASResponse) draftText(card,'p','Ответ NAS: '+s.NASResponse+' · Error-Cause: '+s.NASCause);
    if(s.Response && s.Response!==s.NASResponse) draftText(card,'p','Результат адаптера: '+s.Response);
    if(s.LastError) draftText(card,'p','Диагностика: '+s.LastError);
    if(s.State==='retrying'&&s.NextAttempt) draftText(card,'p','Следующая попытка: '+date(s.NextAttempt));
    if(['pending','sending','awaiting_stop','timeout'].includes(s.State)) draftText(card,'p','Срок ожидания: '+date(s.DeadlineAt));
  }
  for(const g of result.PendingGrants||[]) {
    const row=document.createElement('article');row.className='draft-entry';section.append(row);
    draftText(row,'h4',g.NAS+' · '+g.Username+' · политика '+g.PolicyID);
    draftText(row,'p',(labels[g.State]||g.State)+' · срок '+date(g.DeadlineAt));
  }
  if(!result.Sessions.length&&!result.PendingGrants?.length) draftText(section,'p','Учтённых сессий для отзыва нет.');
  if(result.Attempts.length) {
    const history=document.createElement('details');section.append(history);
    draftText(history,'summary','История попыток · '+result.Attempts.length);
    if(result.AttemptsTruncated) draftText(history,'p','Показаны последние 200 попыток. Полная история сохранена в базе.');
    for(const a of result.Attempts) {
      const row=document.createElement('article');row.className='draft-entry';history.append(row);
      draftText(row,'p',date(a.At)+' · '+a.NAS+' / '+a.ID+' · поколение '+a.Generation);
      draftText(row,'p',(a.NASResponse||'Нет подтверждённого ответа NAS')+(a.NASResponse?' · Error-Cause '+a.NASCause:'')+(a.Response&&a.Response!==a.NASResponse?' · '+a.Response:''));
      if(a.Message) draftText(row,'p',a.Message);
    }
  }
}
