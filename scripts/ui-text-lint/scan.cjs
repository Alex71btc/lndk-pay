// Parse shipped JavaScript without executing any page, handler, or API request.
"use strict";
const fs = require("node:fs");
const {parse} = require("acorn");
const units = JSON.parse(fs.readFileSync(0, "utf8"));
const findings = [];
const textProperties = new Set(["textContent", "innerText", "title", "placeholder", "ariaLabel", "alt"]);
const attrNames = new Set(["aria-label", "title", "placeholder", "alt"]);
const keyProperties = new Set(["i18n", "i18nPlaceholder", "i18nTitle", "i18nAriaLabel", "i18nAlt"]);
function nameOf(node) {
  if (node?.type === "Identifier") return node.name;
  if (node?.type === "MemberExpression") return node.computed ? node.property.value : node.property.name;
}
function literal(node) { return node?.type === "Literal" && typeof node.value === "string"; }
function inspect(unit) {
  let tree;
  try {
    tree = parse(unit.source, {ecmaVersion: "latest", locations: true, allowReturnOutsideFunction: true});
  } catch (error) {
    findings.push({...unit.location, kind: "syntax", value: error.message,
      line: unit.location.line + (error.loc?.line || 1) - 1});
    return;
  }
  function record(kind, value, node) {
    if (value) findings.push({...unit.location, kind, value,
      line: unit.location.line + node.loc.start.line - 1});
  }
  const prefix = unit.location.scope;
  // String-valued wrappers with a documented argument contract.
  const translators = {
    __t: 0, setUiText: 1, setLabel: 1, setValueOrLabel: 2, showIntentStatus: 0,
    showLandingToast: 0, showAliasToast: 0, copyWithToast: 1, addAction: 0,
    ...(prefix === "console" ? {setStatus: 0, copyText: 1} : {}),
  };
  const visibleCalls = {alert: 0, confirm: 0, prompt: 0, createTextNode: 0,
    ...(prefix === "pay" ? {setStatus: 0, copyText: 1} : {})};

  function inspectValue(node, bindings, kind, seen = new Set()) {
    if (!node || seen.has(node)) return;
    const visited = new Set(seen).add(node);
    const part = item => inspectValue(item, bindings, kind, visited);
    if (literal(node)) {
      const html = /<(?:div|span|button|a|p|section|strong|label|input|option|br|li)\b/i.test(node.value);
      record(html ? "html" : kind, node.value, node);
    } else if (node.type === "TemplateLiteral") {
      const raw = node.quasis.map(q => q.value.cooked || "").join("￼");
      if (kind === "key" && node.expressions.length) {
        record("family", raw, node);
      } else {
        const html = /<[a-z][a-z0-9-]*[\s>]/i.test(raw);
        record(html ? "html" : kind, raw, node);
        // Ignore template expression slots inside markup attributes (classes and IDs).
        let before = "";
        node.expressions.forEach((expr, i) => {
          before += node.quasis[i].value.cooked;
          if (!html || before.lastIndexOf("<") <= before.lastIndexOf(">")) part(expr);
          else if (/data-i18n(?:-title|-aria-label|-placeholder|-alt)?=["']$/.test(before)) {
            inspectValue(expr, bindings, "key", visited);
          }
        });
      }
    } else if (node.type === "Identifier") {
      part(bindings[node.name]);
    } else if (node.type === "ConditionalExpression") {
      part(node.consequent); part(node.alternate);
    } else if (node.type === "LogicalExpression" || (node.type === "BinaryExpression" && node.operator === "+")) {
      const left = node.left;
      if (node.operator === "||" && left.type === "MemberExpression" && left.object.name === "scriptOptions") {
        const attr = "data-" + String(nameOf(left)).replace(/[A-Z]/g, c => "-" + c.toLowerCase());
        const override = unit.pwaLabels?.[attr];
        if (override) { record(kind, override, left); return; }
      }
      part(node.left); part(node.right);
    } else if (node.type === "ArrayExpression") {
      node.elements.forEach(part);
    } else if (node.type === "ChainExpression" || node.type === "ArrowFunctionExpression") {
      part(node.expression || node.body);
    } else if (node.type === "MemberExpression" && node.object.type === "Identifier") {
      const obj = bindings[node.object.name];
      if (obj?.type === "ObjectExpression") {
        obj.properties.filter(p => node.computed || p.key?.name === nameOf(node))
          .forEach(p => part(p.value));
      }
    }
  }
  function visit(node, bindings) {
    if (!node || typeof node.type !== "string") return;
    const name = nameOf(node.callee);
    const args = node.arguments || [];
    if (/Function/.test(node.type) || node.type === "BlockStatement") {
      bindings = Object.create(bindings);
      for (const param of node.params || []) if (param.type === "Identifier") bindings[param.name] = null;
    }
    if (node.type === "VariableDeclarator" && node.id.type === "Identifier") {
      bindings[node.id.name] = node.init;
    }
    if (node.type === "CallExpression") {
      if (Object.hasOwn(translators, name)) inspectValue(args[translators[name]], bindings, "key");
      if (Object.hasOwn(visibleCalls, name)) inspectValue(args[visibleCalls[name]], bindings, "raw");
      if (name === "setAttribute" && attrNames.has(args[0]?.value)) inspectValue(args[1], bindings, "raw");
      if (name === "insertAdjacentHTML") inspectValue(args[1], bindings, "html");
      if (name === "loginText") {
        const before = findings.length;
        inspectValue(args[0], bindings, "key");
        for (const out of findings.slice(before)) out.value = "login." + out.value;
      }
    }
    if (node.type === "AssignmentExpression") {
      const prop = nameOf(node.left);
      if (textProperties.has(prop)) inspectValue(node.right, bindings, "raw");
      if (prop === "innerHTML" || prop === "outerHTML") inspectValue(node.right, bindings, "html");
      if (keyProperties.has(prop) && nameOf(node.left.object) === "dataset") inspectValue(node.right, bindings, "key");
    }
    // Covers fragments assembled in helpers before they reach innerHTML.
    const markup = literal(node) ? node.value :
      node.type === "TemplateLiteral" ? node.quasis.map(q => q.value.cooked || "").join("￼") : "";
    if (/^\s*<(?:div|span|button|input|label|section|strong|p|a|li|option)\b/i.test(markup)) {
      inspectValue(node, bindings, "html");
    }
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) value.forEach(child => visit(child, bindings));
      else if (value?.type) visit(value, bindings);
    }
  }
  visit(tree, Object.create(null));
}
for (const unit of units) inspect(unit);
process.stdout.write(JSON.stringify(findings));
