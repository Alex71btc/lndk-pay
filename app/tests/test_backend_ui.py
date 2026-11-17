"""Execute selection and activity merging logic in Node without a live wallet."""
import re
import subprocess
import unittest
from pathlib import Path

APP = Path(__file__).resolve().parents[1]


def run(script):
    result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
    if result.returncode:
        raise AssertionError(result.stderr)


class BackendUiTests(unittest.TestCase):
    def test_selection_hides_credentials_without_changing_saved_backend(self):
        source = (APP/'assets/lightning-backend.js').read_text()
        function = source[source.index('  function updateSelection()'):source.index('  async function refresh()')]
        run('''
const assert = require('node:assert/strict');
let current = {active:'lnd-default'};
const t = key => key;
const inputs = [{value:'http://phoenixd:9740'},{value:'saved-draft'}];
const elements = {
 lightningBackendSelect:{value:'lnd-default'},
 phoenixdFields:{querySelectorAll:()=>inputs}, lndBackendHint:{}, backendUnsaved:{}
};
const document = {getElementById:id=>elements[id]};
''' + function + '''
updateSelection();
assert.equal(elements.phoenixdFields.hidden,true);
assert.equal(inputs[0].disabled,true);
assert.equal(elements.backendUnsaved.textContent,'');
elements.lightningBackendSelect.value='phoenixd'; updateSelection();
assert.equal(elements.phoenixdFields.hidden,false);
assert.equal(inputs[0].disabled,false);
assert.equal(inputs[0].value,'http://phoenixd:9740');
assert.equal(current.active,'lnd-default');
assert.equal(elements.backendUnsaved.textContent,'unsaved');
current.active='phoenixd-test'; updateSelection();
assert.equal(elements.backendUnsaved.textContent,'');
''')

    def test_activity_keeps_both_backend_rows_when_loading_and_refreshing(self):
        source=(APP/'frontend/admin/index.html').read_text()
        functions=source[source.index('      function txHistoryIdentity'):source.index('      async function syncTxHistory()')]
        run('''
const assert=require('node:assert/strict');
const hash='a'.repeat(64);
const lnd={backend_id:'lnd-default',direction:'incoming',payment_hash:hash};
const phoenix={backend_id:'phoenixd-test',direction:'outgoing',payment_hash:hash};
let txHistoryItems=[lnd],txHistoryHasMore=true;
const TX_HISTORY_PAGE_SIZE=50;
let next={items:[phoenix],has_more:false};
const fetchTxHistoryPage=async()=>next;
''' + functions + '''
(async()=>{
 await loadMoreTxHistory();
 assert.equal(txHistoryItems.length,2);
 next={items:[{...phoenix,status:'settled'}],has_more:false};
 await loadTxHistory();
 assert.equal(txHistoryItems.length,2);
 assert.equal(txHistoryItems[0].status,'settled');
 assert.equal(txHistoryItems[1].backend_id,'lnd-default');
 await loadMoreTxHistory(); assert.equal(txHistoryItems.length,2);
})().catch(e=>{console.error(e);process.exitCode=1});
''')

    def test_invoice_strings_are_technical_but_addresses_remain_visible(self):
        source=(APP/'frontend/admin/index.html').read_text()
        function=re.search(r'          function isTechnicalIdentifier\(value\) \{.*?^          \}',source,re.S|re.M).group()
        run("const assert=require('node:assert/strict');\n"+function+'''
for(const invoice of ['lnbc210n1abc','lntb1abc','lnbcrt1abc','LIGHTNING:LNBC1ABC']) {
 assert.equal(isTechnicalIdentifier(invoice),true);
}
assert.equal(isTechnicalIdentifier('alice@example.com'),false);
assert.equal(isTechnicalIdentifier('Coffee donation'),false);
''')

    def test_merged_scanner_keeps_lnurl_and_automatic_decode(self):
        source=(APP/'frontend/admin/index.html').read_text()
        function=source[source.index('      function applyScanResult('):source.index("      window.addEventListener('lightning:scan-lnurl'")]
        run('''
const assert=require('node:assert/strict');
let scanTarget='lnurl',closed=0,decoded=0,events=[];
const field={value:'',focus(){}};
const scannerModal={classList:{contains:()=>true}};
const normalizeScannedText=x=>x.trim();
const setStatus=()=>{};
const window={__t:x=>x,dispatchEvent:e=>events.push(e.type)};
const document={getElementById:()=>field};
const payOfferInput={value:'',dispatchEvent(){}};
const decodeInput={value:''};
const closeScanner=()=>{closed++};
const decodeOffer=()=>{assert.ok(closed>0);decoded++};
''' + function + '''
applyScanResult(' lnurl1auth ');
assert.equal(field.value,'lnurl1auth');
assert.deepEqual(events,['lightning:lnurl-scanned']);
assert.equal(decoded,0);
scanTarget='decode';applyScanResult(' lno1offer ');
assert.equal(decodeInput.value,'lno1offer');assert.equal(decoded,1);
scanTarget='pay';applyScanResult(' lnbc1invoice ');
assert.equal(payOfferInput.value,'lnbc1invoice');assert.equal(decoded,1);
assert.equal(closed,3);
''')
