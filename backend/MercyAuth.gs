/**
 * Tienda Mercy - modulo de autenticacion para integrar al Apps Script existente.
 * No reemplaza doPost ni las operaciones actuales: llamar mercyAuthDispatch(action,data).
 * Script Properties requeridas: MERCY_AUTH_PEPPER (secreto aleatorio largo),
 * MERCY_ADMIN_RECOVERY_EMAIL y MERCY_ADMIN_BOOTSTRAP_HASH.
 * MERCY_ADMIN_BOOTSTRAP_HASH: hash PBKDF2 generado fuera de Apps Script, formato
 * salt:hash. Recomendado migrar a un proveedor de identidad si se requiere MFA.
 * IMPORTANTE: Apps Script no ofrece PBKDF2 nativo; este modulo utiliza SHA-256
 * iterado con sal y pepper del servidor, no equivalente a Argon2/PBKDF2.
 */
const MERCY_AUTH_USERS='MERCY_AUTH_USERS_V1';
const MERCY_AUTH_SESSIONS='MERCY_AUTH_SESSIONS_V1';
const MERCY_AUTH_RECOVERY='MERCY_AUTH_RECOVERY_V1';
function mercyAuthProps_(){return PropertiesService.getScriptProperties()}
function mercyAuthJson_(k){try{return JSON.parse(mercyAuthProps_().getProperty(k)||'{}')}catch(e){return {}}}
function mercyAuthSave_(k,v){mercyAuthProps_().setProperty(k,JSON.stringify(v))}
function mercyAuthHex_(bytes){return bytes.map(b=>('0'+(b&255).toString(16)).slice(-2)).join('')}
function mercyAuthRandom_(){return Utilities.getUuid()+Utilities.getUuid()}
function mercyAuthHash_(secret,salt){
 const pepper=mercyAuthProps_().getProperty('MERCY_AUTH_PEPPER');
 if(!pepper||pepper.length<32)throw Error('Falta MERCY_AUTH_PEPPER de al menos 32 caracteres');
 let value=String(secret)+'|'+salt+'|'+pepper;
 for(let i=0;i<12000;i++)value=mercyAuthHex_(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256,value));
 return value;
}
function mercyAuthEqual_(a,b){a=String(a||'');b=String(b||'');if(a.length!==b.length)return false;let x=0;for(let i=0;i<a.length;i++)x|=a.charCodeAt(i)^b.charCodeAt(i);return x===0}
function mercyAuthPassword_(value){if(typeof value!=='string'||value.length<12||value.length>128)throw Error('La contraseña debe tener entre 12 y 128 caracteres')}
function mercyAuthInitAdmin_(){
 const p=mercyAuthProps_(),users=mercyAuthJson_(MERCY_AUTH_USERS);
 if(users.admin)return users;
 const password=p.getProperty('MERCY_ADMIN_INITIAL_PASSWORD');
 if(!password)throw Error('Configura MERCY_ADMIN_INITIAL_PASSWORD para activar la cuenta admin');
 mercyAuthPassword_(password);
 const salt=mercyAuthRandom_();
 users.admin={name:'Administrador TI',role:'admin',active:true,salt,hash:mercyAuthHash_(password,salt),mustChange:true,recoveryEmail:'jm.michaelflores@gmail.com',failed:0,lockedUntil:0};
 mercyAuthSave_(MERCY_AUTH_USERS,users);
 p.deleteProperty('MERCY_ADMIN_INITIAL_PASSWORD');
 return users;
}
function mercyAuthSession_(token){
 const sessions=mercyAuthJson_(MERCY_AUTH_SESSIONS),key=mercyAuthHash_(String(token||''),'session'),s=sessions[key];
 if(!s||s.expires<Date.now())throw Error('Sesión inválida o expirada');
 const u=mercyAuthJson_(MERCY_AUTH_USERS)[s.user];
 if(!u||!u.active)throw Error('Cuenta deshabilitada');
 return {user:s.user,role:u.role,mustChange:!!u.mustChange,sessionKey:key};
}
function mercyAuthRequire_(token,roles){
 const s=mercyAuthSession_(token);
 if(s.mustChange)throw Error('Debes cambiar tu contraseña primero');
 if(roles&&!roles.includes(s.role))throw Error('No tienes permisos para esta operación');
 return s;
}
function mercyAuthDispatch(action,data){
 data=data||{};
 const lock=LockService.getScriptLock();lock.waitLock(15000);
 try{return mercyAuthHandle_(action,data)}
 catch(e){return {ok:false,error:String(e.message||e)}}
 finally{lock.releaseLock()}
}
function mercyAuthHandle_(action,data){
 const users=mercyAuthInitAdmin_(),now=Date.now();
 if(action==='authLogin'){
  const id=String(data.username||'').trim().toLowerCase(),u=users[id];
  if(!u||!u.active)throw Error('Credenciales inválidas');
  if((u.lockedUntil||0)>now)throw Error('Cuenta temporalmente bloqueada');
  const valid=mercyAuthEqual_(mercyAuthHash_(String(data.password||''),u.salt),u.hash);
  if(!valid){u.failed=(u.failed||0)+1;if(u.failed>=5){u.lockedUntil=now+15*60000;u.failed=0}mercyAuthSave_(MERCY_AUTH_USERS,users);throw Error('Credenciales inválidas')}
  u.failed=0;u.lockedUntil=0;mercyAuthSave_(MERCY_AUTH_USERS,users);
  const token=mercyAuthRandom_(),sessions=mercyAuthJson_(MERCY_AUTH_SESSIONS);
  sessions[mercyAuthHash_(token,'session')]={user:id,expires:now+8*3600000};
  mercyAuthSave_(MERCY_AUTH_SESSIONS,sessions);
  return {ok:true,token,user:id,role:u.role,mustChange:!!u.mustChange};
 }
 if(action==='authRecover'){
  const id=String(data.username||'').trim().toLowerCase();
  if(id==='admin'){
   const u=users.admin,code=String(Math.floor(100000+Math.random()*900000)),salt=mercyAuthRandom_();
   const recovery=mercyAuthJson_(MERCY_AUTH_RECOVERY);
   recovery.admin={salt,hash:mercyAuthHash_(code,salt),expires:now+600000,tries:0};
   mercyAuthSave_(MERCY_AUTH_RECOVERY,recovery);
   MailApp.sendEmail(u.recoveryEmail,'Tienda Mercy: recuperación de administrador','Código de recuperación (válido por 10 minutos): '+code+'\nSi no lo solicitaste, ignora este mensaje.');
  }
  return {ok:true,message:'Si la cuenta permite recuperación, se enviará un código.'};
 }
 if(action==='authReset'){
  if(String(data.username||'').trim().toLowerCase()!=='admin')throw Error('Recuperación no disponible');
  const recovery=mercyAuthJson_(MERCY_AUTH_RECOVERY),r=recovery.admin;
  if(!r||r.expires<now||r.tries>=5)throw Error('Código vencido o bloqueado');
  r.tries++;mercyAuthSave_(MERCY_AUTH_RECOVERY,recovery);
  if(!mercyAuthEqual_(mercyAuthHash_(String(data.code||''),r.salt),r.hash))throw Error('Código inválido');
  mercyAuthPassword_(data.newPassword);
  const u=users.admin;u.salt=mercyAuthRandom_();u.hash=mercyAuthHash_(data.newPassword,u.salt);u.mustChange=false;u.failed=0;u.lockedUntil=0;
  mercyAuthSave_(MERCY_AUTH_USERS,users);delete recovery.admin;mercyAuthSave_(MERCY_AUTH_RECOVERY,recovery);
  const sessions=mercyAuthJson_(MERCY_AUTH_SESSIONS);Object.keys(sessions).forEach(k=>{if(sessions[k].user==='admin')delete sessions[k]});mercyAuthSave_(MERCY_AUTH_SESSIONS,sessions);
  return {ok:true};
 }
 if(action==='authChangePassword'){
  const s=mercyAuthSession_(data.token),u=users[s.user];
  if(!mercyAuthEqual_(mercyAuthHash_(String(data.oldPassword||''),u.salt),u.hash))throw Error('Contraseña anterior incorrecta');
  mercyAuthPassword_(data.newPassword);u.salt=mercyAuthRandom_();u.hash=mercyAuthHash_(data.newPassword,u.salt);u.mustChange=false;
  mercyAuthSave_(MERCY_AUTH_USERS,users);return {ok:true};
 }
 if(action==='authMe'){const s=mercyAuthSession_(data.token);return {ok:true,user:s.user,role:s.role,mustChange:s.mustChange}}
 if(action==='authLogout'){const s=mercyAuthSession_(data.token),sessions=mercyAuthJson_(MERCY_AUTH_SESSIONS);delete sessions[s.sessionKey];mercyAuthSave_(MERCY_AUTH_SESSIONS,sessions);return {ok:true}}
 if(action==='authListUsers'){
  mercyAuthRequire_(data.token,['admin']);return {ok:true,users:Object.keys(users).map(id=>({username:id,name:users[id].name,role:users[id].role,active:users[id].active}))};
 }
 if(action==='authSaveUser'){
  mercyAuthRequire_(data.token,['admin']);
  const id=String(data.username||'').trim().toLowerCase();
  if(!/^[a-z0-9._-]{3,40}$/.test(id))throw Error('Nombre de usuario inválido');
  if(id==='admin')throw Error('La cuenta admin está protegida');
  if(!['admin_negocio','usuario'].includes(data.role))throw Error('Rol no permitido');
  if(users[id]&&!data.password){users[id].role=data.role;users[id].name=String(data.name||id).slice(0,100);users[id].active=data.active!==false}
  else{mercyAuthPassword_(data.password);const salt=mercyAuthRandom_();users[id]={name:String(data.name||id).slice(0,100),role:data.role,active:data.active!==false,salt,hash:mercyAuthHash_(data.password,salt),mustChange:true,failed:0,lockedUntil:0}}
  mercyAuthSave_(MERCY_AUTH_USERS,users);return {ok:true};
 }
 throw Error('Acción de autenticación no reconocida');
}
