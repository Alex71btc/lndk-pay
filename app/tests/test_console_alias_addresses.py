"""The manager must copy/QR the BIP353 address, not its HTTPS fallback."""
import subprocess
import unittest
from pathlib import Path


class ConsoleAliasAddressTests(unittest.TestCase):
    def test_distinct_domains_remain_distinct_in_rendered_actions(self):
        html = (Path(__file__).resolve().parents[1] / 'frontend/public/index.html').read_text()
        function = html[html.index('function renderAliasList('):html.index('    async function loadAliases()')]
        script = r'''
const assert = require('node:assert/strict');
const node = () => ({children:[],dataset:{},style:{},classList:{add(){}},nodes:{},
  querySelector(key){return this.nodes[key] ||= node();},
  appendChild(child){this.children.push(child);}, append(child){this.appendChild(child);},
  prepend(child){this.children.unshift(child);},
  replaceChildren(...children){this.children=children;},
  addEventListener(name, callback){this[name]=callback;}});
const document={createElement:node};
const window={__t:key=>key,applyTranslations(){}};
const aliasList=node(), copied=[], qr=[];
const setLabel=(element,key)=>{element.key=key;};
const setValueOrLabel=(element,value)=>{element.textContent=value;};
const shortenMiddle=x=>x;
const aliasPublicUrl=name=>'https://startos.example.com/alias/'+name;
const copyAliasAddress=address=>copied.push(address);
const showAliasAddressQr=(name,address)=>qr.push(address);
'''+function+r'''
renderAliasList([{name:'alice',address:'alice@startos.example.com',
  bip353_address:'alice@example.com',lnurl_address:'alice@startos.example.com',
  published:true,dns_name:'alice.user._bitcoin-payment.example.com'}]);
const card=aliasList.children[0];
assert.ok(card.querySelector('.aliasTitle').textContent.includes('alice@example.com'));
const fallback=card.querySelector('.aliasMeta').children[0];
assert.equal(fallback.children[1].textContent,' alice@startos.example.com');
const actions=card.querySelector('.aliasActions').children;
actions.find(action=>action.key==='list.copy_address').click();
actions.find(action=>action.key==='list.address_qr').click();
assert.deepEqual(copied,['alice@example.com']);
assert.deepEqual(qr,['alice@example.com']);
'''
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
