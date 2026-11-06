// Moto Rush Online — servidor sem dependências (só Node 18+)
// Uso: node server.js  → abre em http://localhost:3000
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=process.env.PORT||3000,MAX=25,RL=+process.env.RATE_LIMIT||8;
const HTML=path.join(__dirname,'Moto_Rush_Mundo_Aberto.html');
const DB=path.join(process.env.DATA_DIR||__dirname,'accounts.json');
let accounts={};try{accounts=JSON.parse(fs.readFileSync(DB,'utf8'))}catch(e){}
let dirty=false;
function flush(){if(!dirty)return;dirty=false;try{fs.writeFileSync(DB+'.tmp',JSON.stringify(accounts));fs.renameSync(DB+'.tmp',DB)}catch(e){console.error('erro ao salvar',e.message)}}
setInterval(flush,5000);
for(const sig of['SIGINT','SIGTERM'])process.on(sig,()=>{flush();process.exit(0)});

const clients=new Set(),fails={};let nextId=0;
const online=()=>{let n=0;for(const c of clients)if(c.user)n++;return n};
const hash=(p,salt)=>crypto.scryptSync(p,salt,32).toString('hex');
const safeEq=(a,b)=>{const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&crypto.timingSafeEqual(x,y)};

const srv=http.createServer((req,res)=>{
  if(req.url==='/'||req.url==='/index.html'){
    fs.readFile(HTML,(e,d)=>{if(e){res.writeHead(500);res.end('HTML do jogo não encontrado');return}
      res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache'});res.end(d)});
  }else if(req.url==='/health'){res.writeHead(200);res.end('ok')}
  else{res.writeHead(404);res.end('404')}
});

// ---- WebSocket mínimo (RFC 6455) ----
function frame(c,op,data){
  const n=data.length;if(n>=65536||c.sock.destroyed)return;
  let h;if(n<126)h=Buffer.from([128|op,n]);else{h=Buffer.alloc(4);h[0]=128|op;h[1]=126;h.writeUInt16BE(n,2)}
  c.sock.write(Buffer.concat([h,data]));
}
const send=(c,o)=>frame(c,1,Buffer.from(JSON.stringify(o)));
const bcast=(o,except)=>{for(const c of clients)if(c.user&&c!==except)send(c,o)};

srv.on('upgrade',(req,sock)=>{
  const key=req.headers['sec-websocket-key'];
  if(req.url!=='/ws'||!key||clients.size>=100){sock.destroy();return}
  const acc=crypto.createHash('sha1').update(key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+acc+'\r\n\r\n');
  const ip=String(req.headers['x-forwarded-for']||req.socket.remoteAddress).split(',')[0].trim();
  const c={sock,buf:Buffer.alloc(0),ip,alive:true,user:null};
  clients.add(c);
  sock.on('data',d=>{c.alive=true;c.buf=Buffer.concat([c.buf,d]);if(c.buf.length>70000){sock.destroy();return}parse(c)});
  sock.on('close',()=>drop(c));sock.on('error',()=>sock.destroy());
  send(c,{t:'hello',n:online(),max:MAX});
});
function parse(c){
  for(;;){
    const b=c.buf;if(b.length<2)return;
    const op=b[0]&15,fin=b[0]&128,masked=b[1]&128;let len=b[1]&127,off=2;
    if(len===126){if(b.length<4)return;len=b.readUInt16BE(2);off=4}
    else if(len===127){c.sock.destroy();return}
    if(!masked||len>65535){c.sock.destroy();return}
    if(b.length<off+4+len)return;
    const mask=b.subarray(off,off+4),data=Buffer.from(b.subarray(off+4,off+4+len));
    for(let i=0;i<len;i++)data[i]^=mask[i&3];
    c.buf=b.subarray(off+4+len);
    if(op===8){c.sock.end();return}
    if(op===9){frame(c,10,data);continue}
    if(op===1&&fin)handle(c,data.toString('utf8'));
  }
}
function drop(c){
  if(!clients.delete(c))return;
  if(c.user){bcast({t:'leave',id:c.id});bcast({t:'count',n:online()})}
}

// ---- lógica do jogo ----
function auth(c,d){
  const now=Date.now(),F=fails[c.ip]||(fails[c.ip]=[]);
  while(F.length&&now-F[0]>60000)F.shift();
  if(F.length>=RL)return send(c,{t:'err',m:'Muitas tentativas. Aguarde 1 minuto.'});
  const u=String(d.u||'').trim(),p=String(d.p||'');
  if(!/^[A-Za-z0-9_]{3,14}$/.test(u))return send(c,{t:'err',m:'Usuário: 3 a 14 letras, números ou _'});
  if(p.length<4||p.length>64)return send(c,{t:'err',m:'Senha: de 4 a 64 caracteres'});
  if(online()>=MAX)return send(c,{t:'err',m:'Servidor cheio ('+MAX+'/'+MAX+'). Tente mais tarde.'});
  const k=u.toLowerCase();let a=accounts[k];
  if(d.t==='reg'){
    F.push(now);
    if(a)return send(c,{t:'err',m:'Esse usuário já existe'});
    const salt=crypto.randomBytes(16).toString('hex');
    a=accounts[k]={name:u,salt,hash:hash(p,salt),money:50,deliv:0,hasGun:false,created:now};dirty=true;
  }else{
    if(!a||!safeEq(a.hash,hash(p,a.salt))){F.push(now);return send(c,{t:'err',m:'Usuário ou senha incorretos'})}
  }
  for(const o of clients)if(o.user===k)return send(c,{t:'err',m:'Essa conta já está online'});
  c.user=k;c.name=a.name;c.id=++nextId;c.x=22;c.z=-196;c.h=0;c.f=1;c.s=0;c.lastChat=0;
  const others=[...clients].filter(o=>o.user&&o!==c).map(o=>({id:o.id,n:o.name,x:o.x,z:o.z,h:o.h,f:o.f}));
  send(c,{t:'ok',id:c.id,n:a.name,money:a.money,deliv:a.deliv,hasGun:!!a.hasGun,count:online(),players:others});
  bcast({t:'join',id:c.id,n:c.name},c);bcast({t:'count',n:online()});
}
function handle(c,txt){
  let d;try{d=JSON.parse(txt)}catch(e){return}
  if(!d||typeof d.t!=='string')return;
  if(!c.user){if(d.t==='reg'||d.t==='login')auth(c,d);return}
  if(d.t==='pos'){
    const x=+d.x,z=+d.z,h=+d.h,s=+d.s;if(![x,z,h,s].every(Number.isFinite))return;
    c.x=Math.max(-300,Math.min(300,x));c.z=Math.max(-300,Math.min(300,z));c.h=h;c.s=s;c.f=d.f?1:0;c.dirty=true;
  }else if(d.t==='chat'){
    const m=String(d.m||'').replace(/[\u0000-\u001f]/g,'').trim().slice(0,80),now=Date.now();
    if(!m||now-c.lastChat<700)return;c.lastChat=now;bcast({t:'chat',n:c.name,m});
  }else if(d.t==='save'){
    const a=accounts[c.user],money=Math.floor(+d.money),deliv=Math.floor(+d.deliv);
    if(!a||!Number.isFinite(money)||!Number.isFinite(deliv)||money<0||deliv<0||money>1e9)return;
    a.money=money;a.deliv=deliv;a.hasGun=!!d.hasGun;dirty=true;
  }
}
setInterval(()=>{ // 10 posições por segundo
  const act=[...clients].filter(c=>c.user),moved=act.filter(c=>c.dirty);
  if(act.length<2||!moved.length)return;
  for(const c of act){const p=moved.filter(o=>o!==c).map(o=>[o.id,o.x,o.z,+o.h.toFixed(3),o.f,+o.s.toFixed(1)]);if(p.length)send(c,{t:'st',p})}
  for(const o of moved)o.dirty=false;
},100);
setInterval(()=>{for(const c of clients){if(!c.alive){c.sock.destroy();continue}c.alive=false;frame(c,9,Buffer.alloc(0))}},30000);

srv.listen(PORT,()=>console.log('Moto Rush Online rodando em http://localhost:'+PORT+' (máx. '+MAX+' jogadores)'));
