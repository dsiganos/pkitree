// Compact-mode keyboard accessibility: cards get button semantics and
// aria-expanded tracking; attributes are removed again in full view.
import fs from "node:fs";
import { dom, repoFile, check, finish } from "./harness.mjs";

function fakeCard(focused){
  const attrs={};
  const cls=new Set(["card", ...(focused?["focus"]:[])]);
  return { attrs,
    classList:{ contains:c=>cls.has(c), toggle:c=>cls.has(c)?(cls.delete(c),false):(cls.add(c),true) },
    setAttribute:(k,v)=>attrs[k]=v, removeAttribute:k=>{ delete attrs[k]; } };
}
const plain=fakeCard(false), focused=fakeCard(true);
dom.forest.classList.contains=()=>true;            // compact mode on
dom.forest.querySelectorAll=()=>[plain,focused];

applyCompactA11y();
check(plain.attrs.tabindex==="0" && plain.attrs.role==="button", "compact: cards focusable buttons");
check(plain.attrs["aria-expanded"]==="false" && focused.attrs["aria-expanded"]==="true",
  "aria-expanded reflects focus state");

toggleCardFocus(plain);
check(plain.attrs["aria-expanded"]==="true" && plain.classList.contains("focus"), "toggle expands + updates ARIA");
toggleCardFocus(plain);
check(plain.attrs["aria-expanded"]==="false", "second toggle collapses + updates ARIA");

dom.forest.classList.contains=()=>false;           // back to full view
applyCompactA11y();
check(!("tabindex" in plain.attrs) && !("role" in plain.attrs) && !("aria-expanded" in plain.attrs),
  "full view: button semantics removed");

// static markup: toggle button state + keyboard/focus wiring present
const html=fs.readFileSync(repoFile("index.html"),"utf8");
check(/id="compactbtn" aria-pressed="false"/.test(html), "compact toggle has aria-pressed");
check(/addEventListener\("keydown",e=>\{\s*if\(e\.key!=="Enter" && e\.key!==" "\)/.test(html), "Enter/Space handler wired");
check(/\.compact \.card:focus-visible\{outline/.test(html), "visible focus outline in compact mode");

finish();
