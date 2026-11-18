"""Warning checks never write DNS; repair is an explicit reviewed button action."""
import subprocess
import unittest
from pathlib import Path


class AliasDnsWarningUiTests(unittest.TestCase):
    def test_read_only_check_dismissal_modal_queue_and_explicit_repair(self):
        html = (Path(__file__).resolve().parents[1]/'frontend/public/index.html').read_text()
        self.assertRegex(html, r'\[hidden\]\s*\{\s*display:\s*none\s*!important;')
        self.assertNotIn('aliasDnsReplaceConfirm', html)
        functions = html[html.index('    function verificationStatusPresentation('):html.index('    // Alias CRUD')]
        functions += html[html.index('    async function refreshAliasOffer('):html.index('    async function deleteAlias(')]
        script = r'''
const assert=require('node:assert/strict');
const node=()=>({children:[],dataset:{},style:{},handlers:{},
  classList:{values:new Set(),add(v){this.values.add(v);},remove(v){this.values.delete(v);},contains(v){return this.values.has(v);}},
  setAttribute(){},replaceChildren(){this.children=[];},appendChild(n){this.children.push(n);},
  append(...nodes){this.children.push(...nodes);},focus(){},addEventListener(name,fn){this.handlers[name]=fn;}});
const document={activeElement:node(),body:node(),createElement:node,addEventListener(){}};
const window={__t:key=>key};
const setupRepairRecordModal=node(),setupDeleteRecordModal=node();
const aliasDnsRepairModal=node(),aliasDnsRepairItems=node(),aliasDnsRepairLaterBtn=node(),
 aliasDnsRepairNowBtn=node(),aliasDnsRepairFeedback=node(),aliasDnsRepairManualHint=node();
const aliasDnsReplaceHint=node(),repairAliasDnsBtn=node(),
 aliasDnsVerificationResult=node(),verifyAliasDnsBtn=node();
let aliasDnsRepairPlan=null,aliasDnsRepairBusy=false,aliasDnsRepairPreviousFocus=null;
let loadedSetupDnsMode='cloudflare',reloads=0;
const store=new Map(),requests=[],responses=[],statuses=[];
const sessionStorage={getItem:k=>store.get(k),setItem:(k,v)=>store.set(k,v)};
const setLabel=(node,key,params)=>{node.textContent=key;node.dataset.i18n=key;};
const setStatus=(...args)=>statuses.push(args);
const errorDetail=error=>error.message;
const readJsonOrThrow=async response=>response.data;
const getCookie=()=> 'csrf-test';
const loadAliases=async()=>{reloads++;};
const fetch=async(url,options={})=>{requests.push({url,options});return responses.shift();};
const item={name:'alice',address:'alice@wallet.example.com',dns_name:'alice.user._bitcoin-payment.wallet.example.com',
  status:'missing',needs_update:true,repairable:true};
const plan={status:'completed',revision:'a'.repeat(64),items:[item]};
const clean={status:'completed',revision:'c'.repeat(64),items:[{...item,status:'present',needs_update:false}]};
'''+functions+r'''
(async()=>{
 responses.push({ok:true,data:plan});await checkAliasDnsAfterUpdate();
 assert.equal(requests.length,1);
 assert.equal(requests[0].options.method,undefined,'automatic check only reads');
 assert.ok(aliasDnsRepairModal.classList.contains('show'));
 assert.equal(repairAliasDnsBtn.hidden,false,'problems stay reachable outside the dialog');
 assert.equal(aliasDnsRepairItems.children.length,1);
 closeAliasDnsWarning();
 responses.push({ok:true,data:plan});await checkAliasDnsAfterUpdate();
 assert.equal(aliasDnsRepairModal.classList.contains('show'),false,'Later suppresses the same issue for this session');
 responses.push({ok:true,data:plan});await repairAliasDnsBtn.handlers.click();
 assert.ok(aliasDnsRepairModal.classList.contains('show'),'manual check can reopen');
 closeAliasDnsWarning(false);
 setupRepairRecordModal.classList.add('show');showAliasDnsWarning(plan,true);
 assert.equal(aliasDnsRepairModal.classList.contains('show'),false,'do not stack over primary-address warning');
 setupRepairRecordModal.classList.remove('show');showPendingAliasDnsWarning();
 assert.ok(aliasDnsRepairModal.classList.contains('show'));
 assert.equal(requests.filter(r=>r.options.method==='POST').length,0,'display and dismissal never write DNS');
 responses.push({ok:true,data:{ok:true,repaired:1,failed:0}});
 responses.push({ok:true,data:clean});
 await repairAliasDnsFromWarning();
 const posts=requests.filter(r=>r.options.method==='POST');
 assert.equal(posts.length,1);
 assert.equal(posts[0].url,'/api/bip353/repair-aliases');
 assert.equal(posts[0].options.headers['X-CSRF-Token'],'csrf-test');
 assert.deepEqual(JSON.parse(posts[0].options.body),{revision:plan.revision,aliases:['alice'],replace_records:{}});
 assert.equal(reloads,1);assert.equal(aliasDnsRepairBusy,false);
 assert.equal(aliasDnsRepairModal.classList.contains('show'),false);
 assert.equal(statuses.at(-1)[0],'alias.dns_repair.done');
 assert.equal(repairAliasDnsBtn.hidden,true,'fresh verification clears the problem action without a reload');
 assert.equal(aliasDnsRepairModal.handlers.click,undefined,'clicking the backdrop must not dismiss unresolved problems');
 showAliasDnsWarning({...plan,items:[{...item,status:'mismatch',repairable:false}]},true);
 assert.equal(aliasDnsRepairNowBtn.hidden,true,'conflicting DNS is not offered for automatic repair');
 assert.equal(aliasDnsRepairManualHint.hidden,false);
 const before=requests.length;await repairAliasDnsFromWarning();assert.equal(requests.length,before);
 closeAliasDnsWarning(false);
 showAliasDnsWarning({...plan,items:[{...item,status:'mismatch',repairable:false,replaceable:true,dns_revision:'b'.repeat(64)}]},true);
 assert.equal(aliasDnsRepairNowBtn.hidden,false);
 assert.equal(aliasDnsReplaceHint.hidden,false,'explain the effect before replacing an existing offer');
 assert.equal(aliasDnsRepairNowBtn.textContent,'alias.dns_repair.replace');
 assert.equal(requests.length,before,'showing the replacement action does not change DNS');
 assert.equal(aliasDnsRepairNowBtn.disabled,false);
 responses.push({ok:true,data:{ok:true,repaired:1,failed:0}},{ok:true,data:clean});
 await aliasDnsRepairNowBtn.handlers.click();
 const replacement=requests.filter(r=>r.options.method==='POST').at(-1);
 assert.deepEqual(JSON.parse(replacement.options.body).replace_records,{alice:'b'.repeat(64)});
 renderAliasDnsVerification(plan);
 const beforeOutage=requests.length,beforeOutageReloads=reloads;
 responses.push({ok:false,data:{detail:'Receiving wallet offline'}});
 await refreshAliasOffer('alice');
 assert.equal(requests.length,beforeOutage+1,'failed renewals are not automatically retried');
 assert.equal(statuses.at(-1)[0],'error.refresh_offer_detail');
 assert.equal(reloads,beforeOutageReloads,'failure leaves the existing alias list intact');
 responses.push({ok:true,data:{address:item.address}},{ok:true,data:clean});
 await refreshAliasOffer('alice');
 assert.equal(requests[beforeOutage+1].url,requests[beforeOutage].url,'same page can retry after recovery');
 assert.equal(statuses.at(-1)[0],'alias.renewed');
 assert.equal(repairAliasDnsBtn.hidden,true,'Renew offer also refreshes DNS status immediately');
 assert.equal(aliasDnsRepairModal.classList.contains('show'),false);
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
