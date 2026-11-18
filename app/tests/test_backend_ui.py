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
    def test_setup_starts_with_backend_and_keeps_version_footer_last(self):
        setup = (APP / 'frontend/public/index.html').read_text()
        script = (APP / 'assets/lightning-backend.js').read_text()
        # Backend panel belongs after the setup heading, before the general settings.
        self.assertIn("setup.querySelector(':scope > section.section')", script)
        self.assertIn('setup.insertBefore(panel, generalSetup)', script)
        self.assertIn('if (generalSetup)', script)
        self.assertIn("panel.id = 'lightningBackendPanel'", script)
        self.assertIn('id="saveBackendBtn"', script)
        self.assertIn('id="saveSetupBtn"', setup)
        setup_body = setup.split('<main class="card" id="setupCard"', 1)[1].split('</main>', 1)[0]
        self.assertLess(setup_body.index('id="saveSetupBtn"'), setup_body.index('id="setupAppVersion"'))
        self.assertIn('<section class="section">', setup_body)

    def test_nwc_activity_preserves_actual_backend_after_method_override(self):
        source = (APP/'frontend/admin/index.html').read_text()
        start = source.index('          const method = item.method;')
        stop = source.index('          const typeText = {', start)
        run('''
const assert = require('node:assert/strict');
const window = {__t: key => key};
function labels(item) {
''' + source[start:stop] + '''
  return {methodLabel, originLabel};
}
// Connection names and the active spending selection must not determine history ownership.
for (const identity of [{method:'nwc'}, {method:'bolt11',origin:'nwc'}]) {
  const phoenix = labels({...identity, backend_id:'phoenixd-test',counterparty:'LND named connection'});
  assert.ok(phoenix.methodLabel.includes('history.nwc'));
  assert.ok(phoenix.methodLabel.endsWith(' · Phoenixd'));
  assert.equal(phoenix.originLabel, '');
  const lnd = labels({...identity, backend_id:'lnd-default',counterparty:'Phoenix named connection'});
  assert.ok(lnd.methodLabel.endsWith(' · LND'));
  assert.ok(labels(identity).methodLabel.endsWith(' · LND'), 'Legacy history stays LND');
}
assert.ok(labels({method:'bolt12',backend_id:'phoenixd-test'}).methodLabel.endsWith(' · Phoenixd'));
''')

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
let txHistoryItems=[lnd],txHistoryHasMore=true,txHistoryScope=0;
const TX_HISTORY_PAGE_SIZE=50;
let next={items:[phoenix],has_more:false};
let fetchTxHistoryPage=async()=>next;
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
 let finishOldRequest;
 fetchTxHistoryPage=()=>new Promise(resolve=>{finishOldRequest=resolve});
 const oldRequest=loadMoreTxHistory();
 txHistoryScope++;
 txHistoryItems=[phoenix];
 finishOldRequest({items:[lnd],has_more:false});
 assert.equal(await oldRequest,null);
 assert.deepEqual(txHistoryItems,[phoenix]);
})().catch(e=>{console.error(e);process.exitCode=1});
''')

    def test_activity_export_uses_wallet_and_local_calendar_day(self):
        source = (APP / 'frontend/admin/index.html').read_text()
        handler = source[source.index('      const txHistoryExportForm ='):source.index('      const txHistorySection =')]
        run('''
const assert = require('node:assert/strict');
process.env.TZ = 'Europe/Berlin';
let submit, requested, filename;
const button = {disabled:false};
const fields = {
 txHistoryExportForm:{addEventListener:(name,fn)=>{submit=fn},querySelector:()=>button},
 txHistoryExportFrom:{value:'2026-03-29'},
 txHistoryExportTo:{value:'2026-03-29'},
 txHistoryExportStatus:{hidden:true},
};
const txHistoryWallet = {value:'phoenixd'};
const document = {
 getElementById:id=>fields[id],
 createElement:()=>({click(){filename=this.download}}),
};
const window = {__t:key=>key};
const fetch = async (path) => {
 requested = new URL(path,'http://localhost');
 return new Response('wallet\\r\\nPhoenixd\\r\\n',{headers:{'content-type':'text/csv'}});
};
''' + handler + '''
(async()=>{
 await submit({preventDefault(){},submitter:button});
 const params=requested.searchParams;
 assert.equal(params.get('wallet'),'phoenixd');
 assert.equal(params.get('since'),String(Date.parse('2026-03-28T23:00:00Z')/1000));
 assert.equal(params.get('before'),String(Date.parse('2026-03-29T22:00:00Z')/1000));
 assert.equal(filename,'bolt12-pay-activity.csv');
 assert.equal(button.disabled,false);
 fields.txHistoryExportFrom.value='2026-03-30';
 await submit({preventDefault(){},submitter:button});
 assert.equal(fields.txHistoryExportStatus.textContent,'history.export_invalid_dates');
 assert.equal(fields.txHistoryExportStatus.hidden,false);
})().catch(error=>{console.error(error);process.exitCode=1});
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

    def test_backend_navigation_has_labels_with_old_or_missing_catalog(self):
        source=(APP/'assets/lightning-backend.js').read_text()
        function=source[source.index('  const navigationFallback'):source.index('  const cookie')]
        run('''
const assert=require('node:assert/strict');
const window={__t:()=>''};
''' + function + '''
assert.equal(t('switch'),'Switch');
assert.equal(t('configure'),'Configure');
window.__t=key=>key;
assert.equal(t('switch'),'Switch');
window.__t=()=> 'Wechseln';
assert.equal(t('switch'),'Wechseln');
''')
