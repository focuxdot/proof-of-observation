// 把 tee-verify.html 里的浏览器 COSE 验证函数逐字搬来，在 Node 的 WebCrypto 上跑，
// 对真 bundle 验证，并与参考实现 verify-attestation-cose.mjs 交叉核对。
import { readFileSync } from 'node:fs';
import { verifyAttestationDoc } from './verify-attestation-cose.mjs';

const te = new TextEncoder();
const b64ToBytes = (b)=>{const s=atob(b);const u=new Uint8Array(s.length);for(let i=0;i<s.length;i++)u[i]=s.charCodeAt(i);return u;};
const bytesToB64 = (u)=>{let s='';for(const b of u)s+=String.fromCharCode(b);return btoa(s);};
const bytesToHex = (u)=>Array.from(u).map(b=>b.toString(16).padStart(2,'0')).join('');
const concat = (a)=>{const n=a.reduce((x,y)=>x+y.length,0);const o=new Uint8Array(n);let p=0;for(const x of a){o.set(x,p);p+=x.length;}return o;};

// ── 以下与 tee-verify.html 逐字一致 ──
function cborDec(b,p){
  const ib=b[p],mt=ib>>5,ai=ib&0x1f;p++;
  const dv=new DataView(b.buffer,b.byteOffset,b.byteLength);
  let len=ai;
  if(ai===24){len=b[p];p++;}else if(ai===25){len=dv.getUint16(p);p+=2;}
  else if(ai===26){len=dv.getUint32(p);p+=4;}else if(ai===27){len=Number(dv.getBigUint64(p));p+=8;}
  switch(mt){
    case 0:return[len,p];case 1:return[-1-len,p];
    case 2:return[b.subarray(p,p+len),p+len];
    case 3:return[new TextDecoder().decode(b.subarray(p,p+len)),p+len];
    case 4:{const a=[];for(let i=0;i<len;i++){let v;[v,p]=cborDec(b,p);a.push(v);}return[a,p];}
    case 5:{const m={};for(let i=0;i<len;i++){let k,v;[k,p]=cborDec(b,p);[v,p]=cborDec(b,p);m[k]=v;}return[m,p];}
    case 6:return cborDec(b,p);
    case 7:{if(ai===20)return[false,p];if(ai===21)return[true,p];return[null,p];}
  }
}
function cborBstr(b){
  if(b.length<24)return concat([Uint8Array.of(0x40|b.length),b]);
  if(b.length<256)return concat([Uint8Array.of(0x58,b.length),b]);
  if(b.length<65536){const h=new Uint8Array(3);h[0]=0x59;new DataView(h.buffer).setUint16(1,b.length);return concat([h,b]);}
  const h=new Uint8Array(5);h[0]=0x5a;new DataView(h.buffer).setUint32(1,b.length);return concat([h,b]);
}
const cborText=(s)=>{const b=te.encode(s);return concat([Uint8Array.of(0x60|b.length),b]);};
function der(b,p){let tag=b[p],i=p+1,len=b[i];i++;if(len&0x80){const n=len&0x7f;len=0;for(let k=0;k<n;k++){len=(len*256)+b[i];i++;}}return{tag,start:p,cstart:i,cend:i+len,end:i+len};}
function derChildren(b,t){const o=[];let p=t.cstart;while(p<t.cend){const c=der(b,p);o.push(c);p=c.end;}return o;}
function ecdsaDerToRaw(d,size){const seq=der(d,0);const[r,s]=derChildren(d,seq);
  const norm=(t)=>{let v=d.subarray(t.cstart,t.cend);while(v.length>size&&v[0]===0)v=v.subarray(1);const o=new Uint8Array(size);o.set(v,size-v.length);return o;};
  return concat([norm(r),norm(s)]);}
function parseCert(c){const top=der(c,0);const[tbs,,sigVal]=derChildren(c,top);
  const tbsBytes=c.subarray(tbs.start,tbs.end);const tch=derChildren(c,tbs);
  const idx=((tch[0].tag&0xff)===0xa0)?6:5;const spkiT=tch[idx];
  return{tbsBytes,spki:c.subarray(spkiT.start,spkiT.end),sigRaw:ecdsaDerToRaw(c.subarray(sigVal.cstart+1,sigVal.cend),48)};}
const ecVerify=async(spki,sigRaw,msg)=>{const k=await crypto.subtle.importKey('spki',spki,{name:'ECDSA',namedCurve:'P-384'},false,['verify']);return crypto.subtle.verify({name:'ECDSA',hash:'SHA-384'},k,sigRaw,msg);};
async function sha256hexColon(b){const h=new Uint8Array(await crypto.subtle.digest('SHA-256',b));return Array.from(h).map(x=>x.toString(16).padStart(2,'0').toUpperCase()).join(':');}
const AWS_NITRO_ROOT_FP='64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B';
async function verifyCoseAttestation(docB64){
  const buf=b64ToBytes(docB64);
  const[cose]=cborDec(buf,0);const[protectedRaw,,payloadRaw,sig]=cose;
  const[doc]=cborDec(payloadRaw,0);
  const leaf=parseCert(doc.certificate);
  const sigStruct=concat([Uint8Array.of(0x84),cborText('Signature1'),cborBstr(protectedRaw),cborBstr(new Uint8Array(0)),cborBstr(payloadRaw)]);
  const sigOk=await ecVerify(leaf.spki,sig,sigStruct);
  const certs=[...doc.cabundle.map(parseCert),leaf];
  let chainOk=true;
  for(let i=1;i<certs.length;i++)chainOk=chainOk&&await ecVerify(certs[i-1].spki,certs[i].sigRaw,certs[i].tbsBytes);
  const root=certs[0];
  const rootSelf=await ecVerify(root.spki,root.sigRaw,root.tbsBytes);
  const fp=await sha256hexColon(doc.cabundle[0]);
  return{sigOk,chainOk,rootSelf,rootPinned:fp===AWS_NITRO_ROOT_FP,
    pcr0:bytesToHex(doc.pcrs[0]),publicKey:doc.public_key?bytesToB64(doc.public_key):null,
    moduleId:doc.module_id,rootFp:fp};
}

// ── 跑 ──
const path = process.argv[2] || '.out/bundle.json';
const bundle = JSON.parse(readFileSync(path,'utf8'));
const docB64 = bundle.proof.attestation;

const browser = await verifyCoseAttestation(docB64);
const ref = verifyAttestationDoc(Buffer.from(docB64,'base64'));

console.log('── 浏览器移植版 (WebCrypto P-384 + 手写 ASN.1) ──');
console.log(browser);
console.log('\n── 参考实现 (node:crypto X509) ──');
console.log({sigOk:ref.sigOk,chainOk:ref.chainOk,rootSelf:ref.rootSelf,rootPinned:ref.rootPinned,pcr0:ref.pcr0,publicKey:ref.publicKey});

const agree =
  browser.sigOk===ref.sigOk && browser.chainOk===ref.chainOk &&
  browser.rootSelf===ref.rootSelf && browser.rootPinned===ref.rootPinned &&
  browser.pcr0===ref.pcr0 && browser.publicKey===ref.publicKey;
const allGreen = browser.sigOk&&browser.chainOk&&browser.rootSelf&&browser.rootPinned;
console.log('\n两实现一致:', agree?'✅':'❌', ' | 浏览器版四项全绿:', allGreen?'✅':'❌',
  ' | 公钥==proof.public_key:', browser.publicKey===bundle.proof.public_key?'✅':'❌');
process.exit(agree&&allGreen?0:1);
