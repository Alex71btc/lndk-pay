const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname,'../assets/payment-notifications.js'),'utf8');
const storage = new Map();
const key = 'bolt12pay.incoming-payment-toast.state.v2';
let now = Date.now();
class Clock extends Date { static now() { return now; } }
let lockTail = Promise.resolve();
const locks = {request(_name, callback) {
  const result = lockTail.then(callback);
  lockTail = result.catch(() => {});
  return result;
}};
const settle = () => new Promise(resolve => setImmediate(resolve));
function surface(path, items, status = 200, options = {}) {
  // sessionStorage is independent for every tab, localStorage is origin-wide.
  const session = options.session || new Map();
  const api = map => ({getItem:k=>map.get(k)??null,setItem:(k,v)=>map.set(k,v),removeItem:k=>map.delete(k)});
  const timers = [], calls = [], navigations = [], handlers = {};
  let nextTimer = 0;
  const node = () => ({children:[],dataset:{},handlers:{},textContent:'',
    setAttribute(){}, appendChild(n){this.children.push(n); n.parent=this;},
    addEventListener(name,cb){this.handlers[name]=cb;},
    replaceChildren(){this.children=[];}, remove(){this.parent.children=this.parent.children.filter(n=>n!==this);}});
  const body = node();
  const window = {__t:(key,values={})=>`${key}:${values.amount || ''}`,
    setTimeout:(fn,delay)=>{const id=++nextTimer;timers.push({id,fn,delay});return id;},
    clearTimeout(id){const index=timers.findIndex(t=>t.id===id);if(index>=0)timers.splice(index,1);},
    location:{assign:url=>navigations.push(url)}};
  const document = {body,hidden:Boolean(options.hidden),createElement:node,
    addEventListener:(name,callback)=>{handlers[name]=callback;}};
  const context = {window,location:{pathname:path},document,
    sessionStorage:api(session), localStorage:options.blockedStorage ? {getItem(){throw Error('disabled');}} : api(storage),
    navigator:{locks},
    fetch:async url=>{calls.push(url);return {status,ok:status===200,json:async()=>({items})};},console,Date:Clock,Set,Number,String,JSON,Array,Boolean,encodeURIComponent};
  vm.runInNewContext(source,context);
  return {body,timers,calls,navigations,setItems:value=>items=value,setStatus:value=>status=value,
    async setHidden(hidden){document.hidden=hidden;handlers.visibilitychange?.();await settle();},
    runAgain(){vm.runInNewContext(source,context);},
    async poll(){const index=timers.findIndex(t=>t.delay===5000);assert.ok(index>=0);timers.splice(index,1)[0].fn();await settle();}};
}
const payment = hash => ({payment_hash:hash.repeat(64),direction:'incoming',status:'settled',method:'bolt12',amount_sat:21000,settled_at:now/1000,notification_comment:'<img src=x onerror=bad()>'});
(async()=>{
  for(const path of ['/', '/alice', '/pay-login','/static/index.html']) {
    const page=surface(path,[]); await settle(); assert.equal(page.calls.length,0);
  }
  const pay=surface('/pay',[payment('a')]); await settle();
  assert.equal(pay.body.children[0].children.length,0,'history is baseline');
  pay.setItems([payment('b'),payment('a')]);await pay.poll();
  const toast=pay.body.children[0].children[0];
  assert.ok(toast.children[0].textContent.includes('21000'));
  assert.ok(toast.children[1].textContent.includes('backend.name_lnd'), 'legacy LND receipts show their backend');
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
  assert.equal(storage.has(key),true,'sign-out preserves hash-only deduplication');
  storage.clear();
  const wallets = surface('/pay', [payment('e')]); await settle();
  wallets.setItems([{...payment('e'), backend_id:'phoenixd-test'}, payment('e')]);
  await wallets.poll();
  assert.equal(wallets.body.children[0].children.length, 1, 'wallets have independent notification IDs');
  assert.ok(wallets.body.children[0].children[0].children[1].textContent.includes('backend.name_phoenixd'), 'Phoenixd receipt shows receiving backend');
  await wallets.body.children[0].children[0].handlers.click();
  assert.equal(wallets.navigations[0], '/pay?view=activity&payment='+'e'.repeat(64)+'&backend=phoenixd-test');
  // A long-lived tab must re-read the shared state before claiming a payment.
  const tabA = surface('/pay', [payment('f')]); await settle();
  const tabB = surface('/app', [payment('f')]); await settle();
  const beforeA = tabA.body.children[0].children.length;
  const beforeB = tabB.body.children[0].children.length;
  tabA.setItems([payment('g')]); tabB.setItems([payment('g')]);
  await Promise.all([tabA.poll(),tabB.poll()]);
  assert.equal(tabA.body.children[0].children.length-beforeA + tabB.body.children[0].children.length-beforeB,1,
    'simultaneous tabs claim each payment once');
  const copiedSession = new Map([
    ['bolt12pay.incoming-payment-toast.seen.v1','[]'],
    ['bolt12pay.incoming-payment-toast.checked',String(now-3600000)],
  ]);
  const reopened = surface('/app',[payment('g')],200,{session:copiedSession}); await settle();
  assert.equal(reopened.body.children[0].children.length,0,'copied v1 tab snapshot cannot replay');
  now += 120000;
  const later = surface('/pay',[payment('h')]); await settle();
  assert.equal(later.body.children[0].children.length,0,'stale monitoring starts a fresh baseline');
  later.setItems([{...payment('i'),settled_at:(now-3600000)/1000},
    {...payment('j'),settled_at:null}]); await later.poll();
  assert.equal(later.body.children[0].children.length,0,'backfill without a recent settlement is silent');
  later.setItems(['k','l','m','n','o'].map(payment)); await later.poll();
  assert.equal(later.body.children[0].children.length,3,'notification bursts stay bounded');
  const fallbackSession = new Map();
  const fallback = surface('/pay',[payment('p')],200,{blockedStorage:true,session:fallbackSession}); await settle();
  fallback.setItems([payment('q')]); await fallback.poll();
  assert.equal(fallback.body.children[0].children.length,1,'blocked localStorage keeps live notifications working');
  const fallbackNavigation = surface('/app',[payment('q')],200,{blockedStorage:true,session:fallbackSession}); await settle();
  assert.equal(fallbackNavigation.body.children[0].children.length,0,'session fallback survives navigation');
  assert.ok(!storage.get(key).includes('notification_comment'),'persistent state contains no payment details');
  storage.clear();
  const foreground = surface('/pay',[]); await settle();
  foreground.runAgain(); await settle();
  assert.equal(foreground.body.children.length,1,'one notification region per document');
  assert.equal(foreground.timers.filter(t=>t.delay===5000).length,1,'duplicate script does not add polling');
  const hidden = surface('/app',[],200,{hidden:true}); await settle();
  assert.equal(hidden.calls.length,0,'hidden tab does not poll or consume notifications');
  const received = payment('r');
  hidden.setItems([received]); await hidden.poll();
  foreground.setItems([received, {...received, method:'bolt11'}]); await foreground.poll();
  assert.equal(foreground.body.children[0].children.length,1,'same response cannot show one hash twice');
  await hidden.setHidden(false);
  assert.equal(hidden.body.children[0].children.length,0,'switching tabs does not replay an already shown payment');
  await foreground.setHidden(true);
  const receivedLater = payment('s');
  foreground.setItems([receivedLater]); await foreground.poll();
  hidden.setItems([receivedLater]); await hidden.poll();
  assert.equal(hidden.body.children[0].children.length,1,'the visible view receives the next payment');
  // A backend import may take longer than 30 seconds. Active monitoring must
  // use the session baseline rather than discard such receipts as stale.
  storage.clear();
  const monitoring = surface('/pay',[]); await settle();
  now += 1000;
  const delayedBolt12 = {...payment('t'), backend_id:'phoenixd-test'};
  for (let i=0;i<12;i++) {now+=5000;await monitoring.poll();}
  const navigated = surface('/app',[]); await settle();
  navigated.setItems([delayedBolt12]); await navigated.poll();
  assert.equal(navigated.body.children[0].children.length,1,'delayed BOLT12 arrival survives navigation and 30 second delay');
  assert.ok(navigated.body.children[0].children[0].children[1].textContent.includes('bolt12_offer'));
  assert.ok(navigated.body.children[0].children[0].children[1].textContent.includes('backend.name_phoenixd'));
  await navigated.poll();
  assert.equal(navigated.body.children[0].children.length,1,'delayed arrival is shown only once');
  console.log('notification lifecycle: public exclusion, navigation, wallet ownership, click target, comments, expiry OK');
})().catch(error=>{console.error(error);process.exitCode=1});
