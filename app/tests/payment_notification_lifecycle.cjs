const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname,'../assets/payment-notifications.js'),'utf8');
const storage = new Map();
const settle = () => new Promise(resolve => setImmediate(resolve));
function surface(path, items, status = 200) {
  const timers = [], calls = [], navigations = [];
  const node = () => ({children:[],dataset:{},handlers:{},textContent:'',
    setAttribute(){}, appendChild(n){this.children.push(n); n.parent=this;},
    addEventListener(name,cb){this.handlers[name]=cb;},
    replaceChildren(){this.children=[];}, remove(){this.parent.children=this.parent.children.filter(n=>n!==this);}});
  const body = node();
  const window = {__t:(key,values={})=>`${key}:${values.amount || ''}`,
    setTimeout:(fn,delay)=>{timers.push({fn,delay});return timers.length;},clearTimeout(){},
    location:{assign:url=>navigations.push(url)}};
  const context = {window,location:{pathname:path},document:{body,createElement:node,addEventListener(){}},
    sessionStorage:{getItem:k=>storage.get(k)??null,setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},
    fetch:async url=>{calls.push(url);return {status,ok:status===200,json:async()=>({items})};},console,Date,Set,Number,String,JSON,Array,Boolean,encodeURIComponent};
  vm.runInNewContext(source,context);
  return {body,timers,calls,navigations,setItems:value=>items=value,setStatus:value=>status=value,
    async poll(){const index=timers.findIndex(t=>t.delay===5000);assert.ok(index>=0);timers.splice(index,1)[0].fn();await settle();}};
}
const payment = hash => ({payment_hash:hash.repeat(64),direction:'incoming',status:'settled',method:'bolt12',amount_sat:21000,settled_at:Date.now()/1000,notification_comment:'<img src=x onerror=bad()>'});
(async()=>{
  for(const path of ['/', '/alice', '/pay-login','/static/index.html']) {
    const page=surface(path,[]); await settle(); assert.equal(page.calls.length,0);
  }
  const pay=surface('/pay',[payment('a')]); await settle();
  assert.equal(pay.body.children[0].children.length,0,'history is baseline');
  pay.setItems([payment('b'),payment('a')]);await pay.poll();
  const toast=pay.body.children[0].children[0];
  assert.ok(toast.children[0].textContent.includes('21000'));
  assert.equal(toast.children[2].textContent,'<img src=x onerror=bad()>','comment is text');
  await toast.handlers.click();
  assert.equal(pay.navigations[0],'/pay?view=activity&payment='+'b'.repeat(64));
  const app=surface('/app',[payment('b'),payment('a')]);await settle();
  assert.equal(app.body.children[0].children.length,0,'no replay after navigation');
  app.setItems([payment('c'),payment('b')]);await app.poll();
  assert.equal(app.body.children[0].children.length,1,'console receives payments');
  const setup=surface('/app',[payment('d'),payment('c')]);await settle();
  assert.equal(setup.body.children[0].children.length,1,'setup receives new payment during navigation');
  setup.setStatus(401);await setup.poll();
  assert.equal(setup.body.children[0].children.length,0,'expired session clears payment details');
  assert.equal(setup.timers.filter(t=>t.delay===5000).length,0,'expired session stops polling');
  assert.equal(storage.has('bolt12pay.incoming-payment-toast.seen.v1'),false);
  console.log('notification lifecycle: public exclusion, navigation, click target, comments, expiry OK');
})().catch(error=>{console.error(error);process.exitCode=1});
