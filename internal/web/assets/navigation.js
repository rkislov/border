'use strict';
(() => {
 const sidebar=document.querySelector('body > aside'),main=document.querySelector('body > main');
 if(!sidebar||!main)return;
 sidebar.id='main-navigation';
 const mobile=matchMedia('(max-width:650px)'),bar=document.createElement('div');bar.className='menu-bar';
 const toggle=document.createElement('button');toggle.type='button';toggle.className='menu-toggle';toggle.setAttribute('aria-controls',sidebar.id);
 for(let i=0;i<3;i++){const line=document.createElement('span');line.setAttribute('aria-hidden','true');toggle.append(line);}
 const brand=document.createElement('a');brand.className='menu-brand';brand.href='./';brand.textContent='◈ BORDER';
 bar.append(toggle,brand);
 const backdrop=document.createElement('div');backdrop.className='menu-backdrop';backdrop.setAttribute('aria-hidden','true');
 document.body.prepend(bar,backdrop);
 let open=!mobile.matches;
 function setOpen(value,returnFocus=false){
  open=value;
  if(!open&&(returnFocus||sidebar.contains(document.activeElement)))toggle.focus();
  document.body.classList.toggle('menu-open',open);
  document.body.classList.toggle('menu-modal',open&&mobile.matches);
  toggle.setAttribute('aria-expanded',String(open));toggle.setAttribute('aria-label',open?'Закрыть меню':'Открыть меню');
  sidebar.inert=!open;main.inert=open&&mobile.matches;
 }
 document.body.classList.add('menu-ready');setOpen(open);
 toggle.onclick=()=>setOpen(!open);
 backdrop.onclick=()=>setOpen(false,true);
 sidebar.addEventListener('click',event=>{if(mobile.matches&&event.target.closest('button[data-view]'))setOpen(false,true);});
 document.addEventListener('keydown',event=>{
  if(event.key==='Escape'&&open){event.preventDefault();setOpen(false,true);return;}
  if(event.key!=='Tab'||!mobile.matches||!open)return;
  const items=[...bar.querySelectorAll('button,a'),...sidebar.querySelectorAll('a,button,input,summary,[tabindex]')].filter(el=>!el.disabled&&el.tabIndex>=0&&el.getClientRects().length);
  const first=items[0],last=items[items.length-1];
  if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}
  else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}
 });
 mobile.addEventListener('change',()=>setOpen(!mobile.matches));
})();
