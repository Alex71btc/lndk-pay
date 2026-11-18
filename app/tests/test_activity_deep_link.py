import re
import subprocess
import unittest
from pathlib import Path

HTML = Path(__file__).resolve().parents[1] / 'frontend/admin/index.html'

class ActivityDeepLinkTests(unittest.TestCase):
    def test_notification_locates_older_payment_without_filtering_history(self):
        html = HTML.read_text()
        function = re.search(r'^      async function openRequestedPayView\(\).*?^      \}', html, re.M | re.S).group()
        script = r'''
const assert = require('node:assert/strict');
const hash = 'a'.repeat(64);
let txHistorySearchQuery = 'previous search', txHistoryItems = ['stale'], txHistoryScope = 0;
let txHistoryHasMore = true, txHistorySearchTimer = 42;
const txHistorySearchInput = {value:'previous search'};
const txHistoryWallet = {value:''};
const section = {open:false};
const makeRow = (backend,direction,paymentHash) => ({
  dataset:{paymentHash,backendId:backend,direction},open:false,
  closest(){return {classList:{add:(name)=>{this.highlighted=name}}}},
  scrollIntoView(){this.scrolled=true},focus(){this.focused=true}
});
const outgoing = makeRow('lnd-default','outgoing',hash);
const incoming = makeRow('lnd-default','incoming',hash);
const phoenix = makeRow('phoenixd-test','incoming',hash);
let rows = [], renderedItems = [], loads = 0, pages = 0, opened = 0;
function clearTimeout(){}
const document = {getElementById:()=>section,querySelectorAll:()=>rows};
function renderTxHistoryItems(items){
  renderedItems = items.slice();
  rows = items.map(item=>item.row);
}
async function loadTxHistory(){
  assert.equal(txHistorySearchQuery,'','must not search by hash');
  assert.equal(txHistorySearchInput.value,'','must not display payment hash');
  loads++;
  txHistoryItems=[{payment_hash:'b'.repeat(64),backend_id:'lnd-default', direction:'incoming',row:makeRow('lnd-default','incoming','b'.repeat(64))}];
  txHistoryHasMore=true;
}
async function loadMoreTxHistory(){
  pages++;
  txHistoryItems.push({payment_hash:hash,backend_id:'lnd-default',direction:'outgoing',row:outgoing});
  txHistoryItems.push({payment_hash:hash,backend_id:'phoenixd-test',direction:'incoming',row:phoenix});
  txHistoryItems.push({payment_hash:hash,backend_id:'lnd-default',direction:'incoming',row:incoming});
  txHistoryHasMore=false;
}
function openPaySection(){opened++}
const window = {location:{search:'?view=activity&payment='+hash+'&backend=lnd',hash:''}};
'''+function+r'''
(async()=>{
  await openRequestedPayView();
  assert.equal(loads,1);assert.equal(pages,1);
  assert.equal(renderedItems.length,4,'surrounding history must remain');
  assert.equal(incoming.open,true);assert.equal(incoming.focused,true);assert.equal(incoming.scrolled,true);
  assert.equal(incoming.highlighted,'txDeepLinkTarget');
  assert.equal(outgoing.open,false);assert.equal(phoenix.open,false);
  assert.equal(txHistoryWallet.value,'','All should remain All');
  assert.equal(opened,0);
  rows=[];incoming.open=false;phoenix.open=false;
  txHistoryWallet.value='lnd';
  window.location.search='?view=activity&payment='+hash+'&backend=phoenixd';
  await openRequestedPayView();
  assert.equal(phoenix.open,true);assert.equal(incoming.open,false);
  assert.equal(txHistoryWallet.value,'phoenixd','incompatible filter changes');
  assert.equal(renderedItems.length,4);
  window.location.search='?view=activity&payment=invalid';
  await openRequestedPayView();assert.equal(opened,1);assert.equal(loads,2);
})().catch(e=>{console.error(e);process.exitCode=1});
'''
        result = subprocess.run(['node','-'],input=script,text=True,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_amount_click_copies_digits_without_toggling_activity(self):
        html = HTML.read_text()
        start = html.index('          const amountButton = div.querySelector(".txAmount");')
        end = html.index('          const repeatButton', start)
        script = r"""
const assert = require('node:assert/strict');
let click;
const div = {querySelector:()=>({addEventListener:(name,handler)=>{assert.equal(name,'click');click=handler}})};
const amountClipboardValue = '21000', copied = [];
const window = {__t:key=>key};
const copyText = async value=>copied.push(value);
""" + html[start:end] + r"""
(async()=>{
 for (const source of ['touch','mouse','keyboard']) {
   let prevented=false,stopped=false;
   await click({preventDefault(){prevented=true},stopPropagation(){stopped=true}});
   assert.equal(prevented,true,source);assert.equal(stopped,true,source);
 }
 assert.deepEqual(copied,['21000','21000','21000']);
})().catch(e=>{console.error(e);process.exitCode=1});
"""
        result = subprocess.run(['node','-'],input=script,text=True,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
