'use strict';
window.borderGuestActivation=async function(token,target,endpoint){
 const messages={pending:'Вход подтверждён. Подключаем устройство к сети…',awaiting_accounting:'Запрос отправлен оборудованию. Ожидаем подтверждение подключения…',active:'Доступ открыт. Можно пользоваться сетью.',manual:'Вход подтверждён. Автоматическое подключение для этого NAS не настроено; переподключитесь к сети.',failed:'Не удалось подтвердить открытие доступа. Обратитесь к администратору сети.',disconnected:'Сетевая сессия завершена.'};
 if(!token){target.textContent=messages.manual;return;}
 let errors=0;
 for(let i=0;i<120;i++){
  try{
   const response=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({Token:token}),signal:AbortSignal.timeout(8000)});
   if(response.status===403){target.textContent='Разрешение истекло или отозвано. Откройте портал заново.';return;}
   if(!response.ok)throw Error('status unavailable');
   const status=await response.json();errors=0;
   target.textContent=messages[status.State]||messages.pending;
   if(['active','manual','failed','disconnected'].includes(status.State))return;
  }catch{if(++errors>=5){target.textContent='Не удаётся проверить подключение. Проверьте связь или обратитесь к администратору.';return;}}
  await new Promise(resolve=>setTimeout(resolve,2000));
 }
 target.textContent=messages.failed;
};
const activation=document.querySelector('#activation-status');
if(activation?.dataset.token)borderGuestActivation(activation.dataset.token,activation,activation.dataset.endpoint);
