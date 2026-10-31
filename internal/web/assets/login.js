'use strict';
const basePath=(location.pathname.match(/^\/(?:t|portal)\/[a-z][a-z0-9-]{0,31}(?=\/)/)||[''])[0];
const scopedFetch=(path,options)=>fetch(basePath+path,options);
(()=>{
 const form=document.querySelector('#login'),mfa=document.querySelector('#mfa-login'),error=document.querySelector('#error');let challenge='';
 async function submit(body,f){const button=f.querySelector('button');button.disabled=true;error.textContent='';try{const r=await scopedFetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(!r.ok)throw Error(await r.text());const v=await r.json();if(v.MFARequired){challenge=v.Challenge;form.hidden=true;mfa.hidden=false;mfa.elements.Code.focus();}else{challenge='';location.href=basePath+'/';}}catch(e){error.textContent=e.message;}finally{button.disabled=false;}}
 form.onsubmit=e=>{e.preventDefault();const body=Object.fromEntries(new FormData(form));form.elements.Password.value='';submit(body,form);};
 mfa.onsubmit=e=>{e.preventDefault();const body={Challenge:challenge,Code:mfa.elements.Code.value};mfa.elements.Code.value='';submit(body,mfa);};
 document.querySelector('#login-back').onclick=()=>{challenge='';mfa.hidden=true;mfa.elements.Code.value='';form.hidden=false;error.textContent='';form.elements.Password.focus();};
})();
