import json
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

class ChannelLiquidityUiTests(unittest.TestCase):
    def test_renderer_ratios_labels_zero_balance_and_text_safety(self):
        source = (ROOT / 'app/assets/channel-liquidity.js').read_text()
        script = r'''
const assert = require('node:assert/strict');
function node(tag) {return {tag,children:[],style:{},attrs:{},textContent:'',
 appendChild(child){this.children.push(child)},replaceChildren(...children){this.children=children},
 setAttribute(name,value){this.attrs[name]=value}}}
const document={createElement:node};
const window={getLang:()=> 'en',__t:(key,params={})=>key+JSON.stringify(params)};
''' + source + r'''
const target=node('div');
window.Bolt12ChannelLiquidity.render(target,[
 {channel_id:'<img onerror=bad()>',outgoing_sat:375,incoming_sat:125},
 {channel_id:'zero',outgoing_sat:0,incoming_sat:0},
 {channel_id:'out',outgoing_sat:1000,incoming_sat:0},
 {channel_id:'in',outgoing_sat:0,incoming_sat:1000},
]);
const overview=target.children[0],list=overview.children[2];
assert.equal(list.children.length,4);
assert.ok(list.children[0].children[0].textContent.includes('<img onerror=bad()>'));
assert.equal(list.children[0].children[0].children.length,0,'channel ID must be text');
for(const [index, barWidth, widths] of [
 [0,'50%',['75%','25%']], [1,'0%',['0%','0%']],
 [2,'100%',['100%','0%']], [3,'100%',['0%','100%']],
]) {
 const bar=list.children[index].children[2];
 assert.equal(bar.attrs.role,'img');assert.ok(bar.attrs['aria-label']);
 assert.equal(bar.style.width,barWidth);
 assert.deepEqual(bar.children.map(node=>node.style.width),widths);
}
assert.equal(overview.children[1].children[0].children[1].textContent,'1,375 sats');
assert.equal(overview.children[1].children[1].children[1].textContent,'1,125 sats');
assert.throws(()=>window.Bolt12ChannelLiquidity.render(target,[{channel_id:'bad',outgoing_sat:-1,incoming_sat:1}]));
assert.equal(target.children[0],overview,'invalid snapshots do not partially overwrite the view');
window.Bolt12ChannelLiquidity.render(target,[{channel_id:'zero',outgoing_sat:0,incoming_sat:0}]);
assert.equal(target.children[0].children[2].children[0].children[2].style.width,'0%');
window.Bolt12ChannelLiquidity.render(target,[]);
assert.equal(target.children[0].children.length,2,'empty channels do not fabricate zero bars');
'''
        result = subprocess.run(['node','-'],input=script,text=True,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_toast_overrides_console_horizontal_button_layout(self):
        console = (ROOT / 'app/frontend/public/index.html').read_text()
        css = (ROOT / 'app/assets/payment-notifications.css').read_text()
        self.assertRegex(console, r'button, a\.btn\s*\{[^}]*display:\s*inline-flex')
        rule = re.search(r'\.paymentToastRegion \.paymentToast\s*\{([^}]+)', css)[1]
        self.assertIn('display:flex',rule)
        self.assertIn('flex-direction:column',rule)
        self.assertIn('white-space:normal',rule)
        for name in ('Title','Category','Comment'):
            self.assertIn('.paymentToastRegion .paymentToast'+name+' { width:100%',css)

    def test_activity_shortcut_has_bolt_and_liquidity_is_last(self):
        html = (ROOT / 'app/frontend/admin/index.html').read_text()
        nav = re.search(r'<button class="secondary activityShortcut".*?</button>',html,re.S)[0]
        actions_start = html.index('<div class="topActions">')
        self.assertLess(html.index('<h1 '), actions_start)
        self.assertEqual(html.index(nav), html.index('<button', actions_start))
        self.assertNotIn('<nav class="activityShortcut">', html)
        self.assertIn("openPaySection('txHistorySection')", html)
        self.assertIn('/assets/icons/bolt.svg',nav)
        self.assertNotIn('liquidity',nav.lower())
        main = html.split('</main>',1)[0]
        self.assertEqual(re.findall(r'<details class="section" id="([^"]+)"',main)[-1], 'liquiditySection')
        self.assertLess(main.index('id="txHistorySection"'),main.index('id="liquiditySection"'))
        self.assertIn('/assets/icons/channel-liquidity.svg',main)
        # Contextual error action still opens the low-priority section directly.
        self.assertIn("link.href = '#liquiditySection'",html)
        self.assertIn("openPaySection('liquiditySection')",html)

    def test_all_five_languages_name_both_sides(self):
        for language in ('en','de','es','fr','pl'):
            catalog=json.loads((ROOT/f'app/i18n/pay/{language}.json').read_text())
            for key in ('title','outgoing','incoming','active_channels','distribution'):
                self.assertTrue(catalog['liquidity.'+key])
