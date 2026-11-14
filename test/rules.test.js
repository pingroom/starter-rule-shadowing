import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateInput, analyzeRules, ruleAudit, requestFor, hash, POLICY_HASH } from '../src/model.js';
import { readJson, atomicJson, acquireLock } from '../src/storage.js';
import { step, localReport, exportAnalysis } from '../src/engine.js';
import { mockApi, CONFIG, ROOM_CODE, OTHER, ASKER, id } from '../src/mock.js';
const example = await readJson(new URL('../examples/policy.json',import.meta.url));
const sample = () => structuredClone(example);
const D = ['principals','resources','actions'];
function policy(specs) {
  return {policyId:'oracle',title:'Offline policy',context:'Finite test domain.',defaultDecision:'deny',dimensions:{principals:[{id:'p0',label:'P0'},{id:'p1',label:'P1'}],resources:[{id:'r0',label:'R0'},{id:'r1',label:'R1'}],actions:[{id:'a',label:'Action'}]},
    rules:specs.map(([pm,rm,decision],i)=>({id:`rule${i}`,label:`Rule ${i}`,decision,match:{principals:[0,1].filter(bit=>pm&(1<<bit)).map(bit=>`p${bit}`),resources:[0,1].filter(bit=>rm&(1<<bit)).map(bit=>`r${bit}`),actions:['a']}}))};
}
// Reference computes each rule's request set, then subtracts the union of
// higher-priority rule sets. Production instead resolves each request directly.
function oracle(input,resolution) {
  const universe=[];for(const p of input.dimensions.principals)for(const r of input.dimensions.resources)for(const a of input.dimensions.actions)universe.push({principals:p.id,resources:r.id,actions:a.id});
  const sets=input.rules.map(rule=>new Set(universe.map((request,index)=>D.every(d=>rule.match[d].indexOf(request[d])!==-1)?index:null).filter(index=>index!==null)));
  const visited=new Set(),effective=input.rules.map(()=>new Set()),order=input.rules.map((_,i)=>i);if(resolution==='last')order.reverse();
  for(const i of order){for(const value of sets[i])if(!visited.has(value))effective[i].add(value);for(const value of sets[i])visited.add(value);}
  return {sets,effective,defaultCount:universe.length-visited.size,decisions:universe.map((_,index)=>{const owner=effective.findIndex(set=>set.has(index));return owner===-1?'deny':input.rules[owner].decision;})};
}
async function setup(t,input=sample()) {
  const directory=await mkdtemp(join(tmpdir(),'rule-domain-'));t.after(()=>rm(directory,{recursive:true,force:true}));const now=()=> '2026-11-14T00:00:00.000Z',api=mockApi(now);
  const options={client:api.client,directory,input,config:CONFIG,token:'offline-fixture-token',room:ROOM_CODE,now};
  return {directory,api,options,run:(extra={})=>step({...options,...extra}),async decide(value){const p=await step(options);api.answer(p.answers[0].questionId,value);return step(options);}};
}
test('independent set-subtraction oracle checks all three-rule two-by-two policies and both resolutions',()=>{
  const specs=[];for(let p=1;p<4;p++)for(let r=1;r<4;r++)for(const decision of ['allow','deny'])specs.push([p,r,decision]);let count=0;
  for(const a of specs)for(const b of specs)for(const c of specs)for(const resolution of ['first','last']){
    const input=policy([a,b,c]),expected=oracle(input,resolution),result=analyzeRules(input,resolution);
    assert.equal(result.defaultCount,expected.defaultCount);assert.deepEqual(result.requests.map(row=>row.decision),expected.decisions);
    for(const [i,rule]of result.rules.entries()){assert.equal(rule.matchingCount,expected.sets[i].size);assert.equal(rule.effectiveCount,expected.effective[i].size);assert.equal(rule.overriddenCount,expected.sets[i].size-expected.effective[i].size);assert.equal(rule.status,expected.effective[i].size===0?'never_effective':expected.effective[i].size===expected.sets[i].size?'unshadowed':'partially_shadowed');}
    const overlaps=[];for(let i=0;i<3;i++)for(let j=i+1;j<3;j++){const intersection=[...expected.sets[i]].filter(v=>expected.sets[j].has(v));if(input.rules[i].decision!==input.rules[j].decision&&intersection.length)overlaps.push({ids:[`rule${i}`,`rule${j}`],size:intersection.length});}
    assert.deepEqual(result.opposingActionOverlaps.map(row=>({ids:row.ruleIds,size:row.requestCount})),overlaps);count++;
  }
  assert.equal(count,11664);
});
test('a union of narrower rules can fully shadow a broader rule without a single superset',()=>{
  const input=policy([[1,3,'allow'],[2,3,'deny'],[3,3,'allow']]),result=analyzeRules(input,'first'),broad=result.rules[2];
  assert.equal(broad.status,'never_effective');assert.equal(broad.matchingCount,4);assert.deepEqual(broad.overriders.map(row=>[row.ruleId,row.count]),[['rule0',2],['rule1',2]]);assert.ok(broad.overriders.every(row=>row.witness));
  assert.equal(analyzeRules(input,'last').rules[2].status,'unshadowed');
});
test('same-action overrides are shadowing findings without opposing-action or output-difference claims',()=>{
  const result=analyzeRules(policy([[3,3,'allow'],[3,3,'allow']]),'first');assert.equal(result.rules[1].status,'never_effective');assert.deepEqual(result.opposingActionOverlaps,[]);assert.deepEqual(result.resolutionDifferences,[]);
});
test('opposing middle rules can overlap even when first and last output decisions agree',()=>{
  const result=analyzeRules(policy([[3,3,'allow'],[3,3,'deny'],[3,3,'allow']]),'first');assert.equal(result.opposingActionOverlaps.length,2);assert.deepEqual(result.resolutionDifferences,[]);assert.equal(result.defaultCount,0);
});
test('default deny, partial shadowing and full request witnesses remain explicit',()=>{
  const result=analyzeRules(sample(),'first');assert.equal(result.domainSize,8);assert.equal(result.defaultCount,1);assert.equal(result.allowCount+result.denyCount,8);assert.ok(result.rules.some(rule=>rule.status==='partially_shadowed'));assert.ok(result.rules.some(rule=>rule.status==='never_effective'));
  for(const row of result.requests){if(row.winnerRuleId===null)assert.equal(row.decision,'deny');else assert.equal(row.winnerRuleId,row.matchedRuleIds[0]);}
  for(const overlap of result.opposingActionOverlaps){const row=result.requests.find(row=>hash(row.request)===hash(overlap.witness));assert.ok(overlap.ruleIds.every(id=>row.matchedRuleIds.includes(id)));}
});
test('dimension and subset ordering canonicalizes but changing rule order changes identity and behavior',()=>{
  const input=sample(),reordered=sample();for(const d of D){reordered.dimensions[d].reverse();for(const rule of reordered.rules)rule.match[d].reverse();}
  assert.deepEqual(validateInput(input),validateInput(reordered));assert.deepEqual(analyzeRules(input,'first'),analyzeRules(reordered,'first'));
  reordered.rules.reverse();assert.notEqual(hash(validateInput(input)),hash(validateInput(reordered)));assert.notDeepEqual(analyzeRules(input,'first').requests.map(row=>row.decision),analyzeRules(reordered,'first').requests.map(row=>row.decision));
});
test('strict schema rejects sparse data, unknown dimension values, duplicate IDs and unsupported matching syntax',()=>{
  for(const mutate of [x=>{x.extra=1;},x=>{x.policyId+='\n';},x=>{x.context='x\u2028y';},x=>{x.title='\ud800';},x=>{x.defaultDecision='allow';},x=>{x.dimensions.extra=[];},x=>{x.dimensions.actions=[];},x=>{x.dimensions.actions=Array(5).fill(x.dimensions.actions[0]);},x=>{delete x.dimensions.principals[0];},x=>{x.dimensions.principals[0].id='constructor';},x=>{x.dimensions.principals[1].id=x.dimensions.principals[0].id;},x=>{x.rules=[];},x=>{x.rules=Array(9).fill(x.rules[0]);},x=>{delete x.rules[0];},x=>{x.rules[0].id='__proto__';},x=>{x.rules[1].id=x.rules[0].id;},x=>{x.rules[0].decision='ALLOW';},x=>{x.rules[0].match.actions=[];},x=>{x.rules[0].match.actions=['*'];},x=>{delete x.rules[0].match.actions[0];},x=>{x.rules[0].match.actions=['read','read'];},x=>{x.rules[0].match.extra=[];}]){const input=sample();mutate(input);assert.throws(()=>validateInput(input));}
  for(const value of ['First','first\n',true,{},undefined])assert.throws(()=>analyzeRules(sample(),value));
});
test('maximum metadata fits one explicit source-bound Question with known resolution buttons',()=>{
  const input=sample();input.policyId='p'.repeat(32);input.title='界'.repeat(32);input.context='界'.repeat(80);input.rules=Array.from({length:8},(_,i)=>({...structuredClone(input.rules[0]),id:'r'+i+'x'.repeat(10),label:'界'.repeat(40)}));
  const req=requestFor(input,CONFIG,'resolution',id(1));assert.ok(req.prompt.length<=500,req.prompt.length);assert.equal(req.data.policy_hash,POLICY_HASH);assert.equal(req.data.rule_order_hash,hash(input.rules.map(rule=>rule.id)));assert.deepEqual(req.options.map(row=>row.value),['first','last','unknown']);assert.ok(req.prompt.includes(input.context));assert.ok(input.rules.every(rule=>req.prompt.includes(rule.id)));
});
test('Unknown or absent semantics withholds every complete diagnostic',()=>{
  for(const choice of [null,'unknown'])assert.deepEqual(ruleAudit(sample(),choice),{status:'incomplete',analysis:null});assert.throws(()=>ruleAudit(sample(),'FIRST'));
});
test('complete SDK audit exports private attributed evidence and remains offline on repeated exports',async t=>{
  const s=await setup(t),result=await s.decide('last');assert.equal(result.status,'complete');assert.equal(result.analysis.resolution,'last');assert.equal(result.answers[0].askerId,ASKER);assert.equal(result.answers[0].responderId,CONFIG.participant.id);assert.ok(result.answers[0].answeredAt);const calls=s.api.calls.length;
  assert.deepEqual((await exportAnalysis(s.directory,s.options.input)).analysis,result.analysis);await localReport(s.directory,s.options.input,{save:true});assert.equal(s.api.calls.length,calls);assert.equal((await stat(join(s.directory,'analysis.json'))).mode&0o777,0o600);assert.equal(result.accessChanged,false);assert.equal(result.rulesRemoved,false);
  const release=await acquireLock(s.directory);await assert.rejects(exportAnalysis(s.directory,s.options.input),/lock exists/);await release();
});
test('Unknown and invalid SDK answers never produce complete exports',async t=>{
  for(const value of ['unknown','invalid']){const s=await setup(t),result=await s.decide(value);assert.equal(result.status,'incomplete');assert.equal(result.analysis,null);await assert.rejects(exportAnalysis(s.directory,s.options.input));assert.equal(await readJson(join(s.directory,'analysis.json')),null);}
});
test('rule order, match domain, decisions, metadata, credentials and saved provenance remain bound',async t=>{
  const s=await setup(t);await s.decide('first');const original=await readJson(join(s.directory,'state.json')),calls=s.api.calls.length;
  for(const mutate of [x=>{x.rules.reverse();},x=>{x.rules[0].decision='deny';},x=>{x.rules[0].match.actions=['edit'];},x=>{x.dimensions.resources[0].label='Other meaning';},x=>{x.context='Other semantics';}]){const input=sample();mutate(input);await assert.rejects(s.run({input}));await assert.rejects(exportAnalysis(s.directory,input));}
  for(const mutate of [x=>{x.attempts[0].observation.answer.value='last';},x=>{x.attempts[0].request.data.rule_order_hash='wrong';}]){const state=structuredClone(original);mutate(state);await atomicJson(s.directory,'state.json',state);await assert.rejects(s.run());await assert.rejects(exportAnalysis(s.directory,s.options.input));}
  await atomicJson(s.directory,'state.json',original);await assert.rejects(s.run({token:'other'}));await assert.rejects(s.run({config:{participant:{id:OTHER,label:'Other'}}}));assert.equal(s.api.calls.length,calls);
});
test('largest64-request/eight-rule audit fits private export bounds and retains every matching rule',async t=>{
  const input=sample();for(const d of D)input.dimensions[d]=Array.from({length:4},(_,i)=>({id:'v'+i+'x'.repeat(10),label:'界'.repeat(24)}));input.rules=Array.from({length:8},(_,i)=>({id:'r'+i+'x'.repeat(10),label:'界'.repeat(40),decision:i%2?'allow':'deny',match:Object.fromEntries(D.map(d=>[d,input.dimensions[d].map(v=>v.id)]))}));input.title='界'.repeat(32);input.context='界'.repeat(80);input.policyId='p'.repeat(32);
  const s=await setup(t,input),result=await s.decide('first');assert.equal(result.analysis.requests.length,64);assert.ok(result.analysis.requests.every(row=>row.matchedRuleIds.length===8));assert.equal(result.analysis.opposingActionOverlaps.length,16);assert.equal(result.analysis.resolutionDifferences.length,64);await exportAnalysis(s.directory,input);const bytes=(await stat(join(s.directory,'analysis.json'))).size;assert.ok(bytes<1024*1024);t.diagnostic(`Maximum audit export: ${bytes} bytes`);
});
