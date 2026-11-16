import re
import subprocess
import unittest
from pathlib import Path

HTML = Path(__file__).resolve().parents[1] / 'frontend/admin/index.html'

class ActivityDeepLinkTests(unittest.TestCase):
    def test_hash_search_opens_exact_older_payment_and_invalid_links_are_ignored(self):
        html = HTML.read_text()
        function = re.search(r'^      async function openRequestedPayView\(\).*?^      \}', html, re.M | re.S).group()
        script = r'''
const assert = require('node:assert/strict');
const hash = 'a'.repeat(64);
let txHistorySearchQuery = '', txHistoryItems = ['newest'];
const txHistorySearchInput = {value:''};
const section = {open:false};
const selected = {dataset:{paymentHash:hash},open:false,scrollIntoView(){this.scrolled=true},focus(){this.focused=true}};
const other = {dataset:{paymentHash:'b'.repeat(64)}};
const document = {getElementById:()=>section,querySelectorAll:()=>[other,selected]};
let rendered = 0, opened = 0;
function openPaySection(){opened++}
const window = {location:{search:'?view=activity&payment='+hash, hash:''},renderTxHistory:async()=>{
  assert.equal(txHistorySearchQuery,hash,'query searches all history, not just latest page');
  assert.equal(txHistoryItems.length,0);rendered++;
}};
'''+function+r'''
(async()=>{
 await openRequestedPayView();
 assert.equal(selected.open,true);assert.equal(selected.focused,true);assert.equal(selected.scrolled,true);
 assert.equal(other.open,undefined);assert.equal(rendered,1);assert.equal(opened,0);
 window.location.search='?view=activity&payment=invalid';
 await openRequestedPayView();assert.equal(rendered,1);assert.equal(opened,1);
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
