const basePath=(location.pathname.match(/^\/(?:t|portal)\/[a-z][a-z0-9-]{0,31}(?=\/)/)||[''])[0];
const scopedFetch=(path,options)=>fetch(basePath+path,options);
'use strict';
document.querySelector('#login').onsubmit=async e=>{e.preventDefault();const b=e.target.querySelector('button');b.disabled=true;try{const r=await scopedFetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.fromEntries(new FormData(e.target)))});e.target.elements.Password.value='';if(!r.ok)throw new Error(await r.text());location.href=basePath+'/';}catch(err){document.querySelector('#error').textContent=err.message;}finally{b.disabled=false;}};
