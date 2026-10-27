'use strict';
self.addEventListener('push',event=>{
 let value={title:'Border',body:'Новое уведомление личного кабинета.'};
 try {if(event.data) value=event.data.json();} catch (_) {}
 event.waitUntil(self.registration.showNotification(value.title,{body:value.body,tag:'border-security'}));
});
self.addEventListener('notificationclick',event=>{
 event.notification.close();
 event.waitUntil(clients.openWindow(self.registration.scope));
});
