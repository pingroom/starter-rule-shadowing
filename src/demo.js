import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { step, exportAnalysis } from './engine.js';
import { mockApi, CONFIG, ROOM_CODE } from './mock.js';
const input = JSON.parse(await readFile(new URL('../examples/policy.json',import.meta.url),'utf8'));
for (const choice of ['first','last','unknown']) {
  const directory = await mkdtemp(join(tmpdir(),'rule-audit-demo-')), now = () => '2026-11-14T00:00:00.000Z', api = mockApi(now);
  const args = {client:api.client,directory,input,config:CONFIG,token:'offline-fixture-token',room:ROOM_CODE,now};
  try {
    const pending = await step(args); api.answer(pending.answers[0].questionId,choice); const result = await step(args);
    if (result.status === 'complete') await exportAnalysis(directory,input);
    console.log(JSON.stringify({scenario:choice,status:result.status,rules:result.analysis?.rules ?? null,opposingActionOverlaps:result.analysis?.opposingActionOverlaps ?? null,resolutionDifferences:result.analysis?.resolutionDifferences ?? null,liveDeliveryTested:false},null,2));
  } finally { await rm(directory,{recursive:true,force:true}); }
}
