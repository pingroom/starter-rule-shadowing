import { createHash } from 'node:crypto';

export const TTL = 900;
export const CLOCK_SKEW_MS = 60000;
export const TOKEN = /^[^\s\x00-\x1f\x7f]{1,8192}(?![\s\S])/;
export const ROOM = /^[A-Z0-9]{12}$(?![\s\S])/;
export const isId = (value) => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/.test(value);
const record = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value, expected) => {
  if (!record(value)) return false;
  const actual = Object.keys(value).sort(), wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
};
const word = (value) => typeof value === 'string' && /^[a-z][a-z0-9_-]{0,39}$(?![\s\S])/.test(value);
const line = (value, max) => typeof value === 'string' && value.length > 0 && value.length <= max && value.isWellFormed()
  && !/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(value) && value.trim() === value;
const canonical = (value) => Array.isArray(value) ? value.map(canonical) : record(value) ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])])) : value;
export const hash = (value) => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');

export function iso(raw) {
  if (typeof raw !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$(?![\s\S])/.test(raw)) throw new Error('Expected a UTC timestamp.');
  const time = Date.parse(raw);
  if (!Number.isFinite(time) || new Date(time).toISOString().slice(0, 19) !== raw.slice(0, 19)) throw new Error('Invalid UTC timestamp.');
  return new Date(time).toISOString();
}


export const POLICY = Object.freeze({ algorithm: 'finite-ordered-rules-v1', dimensions: ['principals','resources','actions'], default: 'deny', matching: 'exact-cartesian-subsets', unknown: 'withhold-complete-analysis' });
export const POLICY_HASH = hash(POLICY);
const DIMENSIONS = ['principals','resources','actions'];
const safeId = value => word(value) && value.length <= 12 && !['constructor','prototype','__proto__'].includes(value);
const compare = (a,b) => a < b ? -1 : a > b ? 1 : 0;
const promptFor = input => `${input.title}\nPolicy ${input.policyId}: ${input.context}\nOrdered rules: ${input.rules.map(rule => rule.id).join(', ')}\nSnapshot ${hash(input).slice(0,16)}. Review the local policy preview.\nWhen multiple rules match, does this policy use the FIRST or LAST matching rule? Unknown = not established. Unmatched requests are denied.`;
export function validateInput(input) {
  if (!keys(input,['policyId','title','context','dimensions','rules','defaultDecision']) || !word(input.policyId) || input.policyId.length > 32 || !line(input.title,32) || !line(input.context,80)
    || !keys(input.dimensions,DIMENSIONS) || !Array.isArray(input.rules) || input.rules.length < 1 || input.rules.length > 8 || input.defaultDecision !== 'deny') throw new Error('Provide policy metadata, three finite dimensions, 1–8 ordered rules and defaultDecision:deny.');
  const dimensions = {};
  for (const dimension of DIMENSIONS) {
    const values = input.dimensions[dimension], ids = new Set();
    if (!Array.isArray(values) || values.length < 1 || values.length > 4) throw new Error('Each request dimension needs 1–4 named values.');
    dimensions[dimension] = Array.from(values, value => {
      if (!keys(value,['id','label']) || !safeId(value.id) || ids.has(value.id) || !line(value.label,24)) throw new Error('Dimension values need unique safe IDs and short labels.');
      ids.add(value.id); return {...value};
    }).sort((a,b) => compare(a.id,b.id));
  }
  const ids = new Set();
  const rules = Array.from(input.rules, rule => {
    if (!keys(rule,['id','label','match','decision']) || !safeId(rule.id) || ids.has(rule.id) || !line(rule.label,40) || !keys(rule.match,DIMENSIONS) || !['allow','deny'].includes(rule.decision)) throw new Error('Rules require unique IDs, labels, exact dimension subsets and allow/deny decisions.');
    ids.add(rule.id); const match = {};
    for (const dimension of DIMENSIONS) {
      const subset = rule.match[dimension], known = new Set(dimensions[dimension].map(value => value.id));
      if (!Array.isArray(subset) || subset.length < 1 || subset.length > known.size || new Set(subset).size !== subset.length || Array.from(subset).some(value => !known.has(value))) throw new Error('Rule match sets must be nonempty distinct subsets of their declared dimensions.');
      match[dimension] = [...subset].sort(compare);
    }
    return {id:rule.id,label:rule.label,match,decision:rule.decision};
  });
  const result = {policyId:input.policyId,title:input.title,context:input.context,dimensions,rules,defaultDecision:'deny'};
  if (promptFor(result).length > 500) throw new Error('Resolution prompt exceeds 500 UTF-16 units.');
  return result;
}
export function validateConfig(config) {
  if (!keys(config,['participant']) || !keys(config.participant,['id','label']) || !isId(config.participant.id) || !line(config.participant.label,60)) throw new Error('Config requires an exact service owner UUID and label.');
  return structuredClone(config);
}
export const tasksFor = input => { validateInput(input); return [{id:'resolution'}]; };
export const optionsFor = () => [['first','First matching rule'],['last','Last matching rule'],['unknown','Unknown']].map(([value,label]) => ({value,label,style:'default'}));
export function requestFor(rawInput,config,taskId,attemptId) {
  const input = validateInput(rawInput); validateConfig(config);
  if (taskId !== 'resolution' || !isId(attemptId)) throw new Error('Invalid resolution task or attempt.');
  const key = `rules-${attemptId}`;
  return {prompt:promptFor(input),context:`To ${config.participant.id}`,options:optionsFor(),responder_scope:'direct',target_user_id:config.participant.id,ttl:TTL,correlation_id:key,
    data:{input_hash:hash(input),rule_order_hash:hash(input.rules.map(rule => rule.id)),policy_hash:POLICY_HASH,task_id:taskId,attempt_id:attemptId},idempotencyKey:key};
}
const matches = (rule,request) => DIMENSIONS.every(dimension => rule.match[dimension].includes(request[dimension]));
/** Pure finite-domain audit; CLI exports additionally require validated owner evidence. */
export function analyzeRules(rawInput,resolution) {
  const input = validateInput(rawInput);
  if (!['first','last'].includes(resolution)) throw new Error('A known first/last resolution policy is required.');
  const domain = input.dimensions;
  const requests = domain.principals.flatMap(principal => domain.resources.flatMap(resource => domain.actions.map(action => {
    const request = {principals:principal.id,resources:resource.id,actions:action.id};
    const matched = input.rules.filter(rule => matches(rule,request));
    const first = matched[0], last = matched.at(-1), winner = resolution === 'first' ? first : last;
    return {request,matchedRuleIds:matched.map(rule => rule.id),winnerRuleId:winner?.id ?? null,decision:winner?.decision ?? input.defaultDecision,
      first:{ruleId:first?.id ?? null,decision:first?.decision ?? input.defaultDecision},last:{ruleId:last?.id ?? null,decision:last?.decision ?? input.defaultDecision}};
  })));
  const rules = input.rules.map((rule,index) => {
    const matching = requests.filter(row => row.matchedRuleIds.includes(rule.id)), effective = matching.filter(row => row.winnerRuleId === rule.id), overridden = matching.filter(row => row.winnerRuleId !== rule.id);
    const overriders = input.rules.filter(candidate => overridden.some(row => row.winnerRuleId === candidate.id)).map(candidate => ({ruleId:candidate.id,count:overridden.filter(row => row.winnerRuleId === candidate.id).length,witness:overridden.find(row => row.winnerRuleId === candidate.id).request}));
    return {ruleId:rule.id,position:index+1,decision:rule.decision,matchingCount:matching.length,effectiveCount:effective.length,overriddenCount:overridden.length,
      status:effective.length === 0 ? 'never_effective' : overridden.length ? 'partially_shadowed' : 'unshadowed',effectiveWitness:effective[0]?.request ?? null,overriddenWitness:overridden[0] ? {request:overridden[0].request,winnerRuleId:overridden[0].winnerRuleId} : null,overriders};
  });
  const opposingActionOverlaps = input.rules.flatMap((left,i) => input.rules.slice(i+1).flatMap(right => {
    if (left.decision === right.decision) return [];
    const overlap = requests.filter(row => row.matchedRuleIds.includes(left.id) && row.matchedRuleIds.includes(right.id));
    return overlap.length ? [{ruleIds:[left.id,right.id],decisions:[left.decision,right.decision],requestCount:overlap.length,witness:overlap[0].request}] : [];
  }));
  const resolutionDifferences = requests.filter(row => row.first.decision !== row.last.decision).map(({request,first,last}) => ({request,first,last}));
  const defaultCount = requests.filter(row => row.winnerRuleId === null).length;
  if (rules.reduce((sum,rule) => sum+rule.effectiveCount,0)+defaultCount !== requests.length || rules.some(rule => rule.effectiveCount+rule.overriddenCount !== rule.matchingCount)) throw new Error('Internal request coverage conservation failure.');
  return {resolution,domainSize:requests.length,defaultDecision:'deny',matchedCount:requests.length-defaultCount,defaultCount,
    allowCount:requests.filter(row => row.decision === 'allow').length,denyCount:requests.filter(row => row.decision === 'deny').length,
    requests,rules,opposingActionOverlaps,resolutionDifferences,sourceHash:hash(input),policyHash:POLICY_HASH,accessChanged:false,rulesRemoved:false};
}
export function ruleAudit(rawInput,choice) {
  const input = validateInput(rawInput);
  if (choice !== null && !optionsFor().some(option => option.value === choice)) throw new Error('Supply first, last, Unknown or missing resolution.');
  return choice === null || choice === 'unknown' ? {status:'incomplete',analysis:null} : {status:'complete',analysis:analyzeRules(input,choice)};
}

export function validateState(state, rawInput) {
  const input = validateInput(rawInput), tasks = tasksFor(input);
  if (!keys(state, ['version', 'inputHash', 'config', 'room', 'credentialHash', 'startedAt', 'attempts']) || state.version !== 1
    || state.inputHash !== hash(input) || typeof state.room !== 'string' || !ROOM.test(state.room)
    || typeof state.credentialHash !== 'string' || state.credentialHash.length !== 64 || !/^[0-9a-f]{64}$/.test(state.credentialHash)
    || !Array.isArray(state.attempts) || state.attempts.length > tasks.length || iso(state.startedAt) !== state.startedAt) {
    throw new Error('Invalid state or changed ordered rules. Restore the original inputs.');
  }
  validateConfig(state.config);
  const ids = new Set(), questionIds = new Set();
  let previous = state.startedAt, askerId;
  for (const [index, attempt] of state.attempts.entries()) {
    if (!keys(attempt, ['id', 'taskId', 'createdAt', 'request', 'questionId', 'status', 'observation'])
      || !isId(attempt.id) || ids.has(attempt.id) || attempt.taskId !== tasks[index].id
      || iso(attempt.createdAt) !== attempt.createdAt || attempt.createdAt < previous
      || hash(attempt.request) !== hash(requestFor(input, state.config, attempt.taskId, attempt.id))
      || !['creating', 'pending', 'answered', 'expired', 'cancelled', 'invalid_answer'].includes(attempt.status)) {
      throw new Error('Invalid saved rule resolution request.');
    }
    ids.add(attempt.id);
    previous = attempt.createdAt;
    if (attempt.status === 'creating') {
      if (attempt.questionId !== null || attempt.observation !== null) throw new Error('Invalid uncertain creation state.');
    } else {
      if (!isId(attempt.questionId) || questionIds.has(attempt.questionId)) throw new Error('Invalid or repeated Question ID.');
      questionIds.add(attempt.questionId);
      validateObservation(attempt.observation, attempt.status, attempt.request);
      if (Date.parse(attempt.observation.createdAt) < Date.parse(attempt.createdAt) - CLOCK_SKEW_MS
        || attempt.observation.checkedAt < attempt.createdAt) throw new Error('Observation predates creation intent.');
      previous = attempt.observation.checkedAt;
      if (askerId !== undefined && attempt.observation.askerId !== askerId) throw new Error('Questions belong to different asking registrations.');
      askerId = attempt.observation.askerId;
    }
    if (['creating', 'pending'].includes(attempt.status) && index !== state.attempts.length - 1) {
      throw new Error('Only the last task may have an active Question.');
    }
  }
  return state;
}

export function report(state,rawInput) {
  const input = validateInput(rawInput); validateState(state,input);
  const attempt = state.attempts[0], answer = attempt?.observation?.answer;
  const evidence = {taskId:'resolution',status:attempt?.status === 'creating' ? 'create_unknown' : attempt?.status ?? 'unasked',choice:answer?.value ?? null,label:answer?.label ?? null,
    questionId:attempt?.questionId ?? null,attemptId:attempt?.id ?? null,responderId:answer?.responderId ?? null,answeredAt:answer?.answeredAt ?? null,askerId:attempt?.observation?.askerId ?? null,observedAt:attempt?.observation?.checkedAt ?? null};
  const calculation = ruleAudit(input,evidence.choice);
  const status = evidence.status === 'unasked' ? 'ready' : ['create_unknown','pending'].includes(evidence.status) ? evidence.status : calculation.status;
  return {policyId:input.policyId,source:input,sourceHash:hash(input),configHash:hash(state.config),policy:POLICY,policyHash:POLICY_HASH,participant:state.config.participant,room:state.room,answers:[evidence],analysis:calculation.analysis,accessChanged:false,rulesRemoved:false,status};
}

function validateObservation(observation, status, request) {
  if (!keys(observation, ['createdAt', 'expiresAt', 'checkedAt', 'askerId', 'resolvedAt', 'answer']) || !isId(observation.askerId)) throw new Error('Invalid saved observation.');
  for (const key of ['createdAt', 'expiresAt', 'checkedAt']) if (iso(observation[key]) !== observation[key]) throw new Error('Invalid saved timestamp.');
  const duration = Date.parse(observation.expiresAt) - Date.parse(observation.createdAt);
  if (duration < TTL * 1000 - 1000 || duration > TTL * 1000 + 1000) throw new Error('Question lifetime differs from the saved request.');
  const latest = Date.parse(observation.checkedAt) + CLOCK_SKEW_MS;
  if (Date.parse(observation.createdAt) > latest) throw new Error('Question creation is implausibly in the future. Check the local clock.');
  if (status === 'pending') {
    if (observation.resolvedAt !== null) throw new Error('Pending Question has a resolution timestamp.');
  } else if (iso(observation.resolvedAt) !== observation.resolvedAt || observation.resolvedAt < observation.createdAt
    || Date.parse(observation.resolvedAt) > latest
    || (status === 'expired' ? observation.resolvedAt < observation.expiresAt : observation.resolvedAt > observation.expiresAt)) throw new Error('Invalid Question resolution time.');
  if (status === 'answered') {
    const answer = observation.answer;
    if (!keys(answer, ['value', 'label', 'responderId', 'answeredAt']) || answer.responderId !== request.target_user_id
      || !request.options.some(option => option.value === answer.value && option.label === answer.label)
      || iso(answer.answeredAt) !== answer.answeredAt || answer.answeredAt !== observation.resolvedAt
      || answer.answeredAt < observation.createdAt || answer.answeredAt > observation.expiresAt) throw new Error('Invalid saved rule resolution evidence.');
  } else if (observation.answer !== null) throw new Error('Unanswered tasks must not contain rule resolution evidence.');
}

export function observeQuestion(q, request, questionId, room, checkedAt) {
  if (!isId(questionId) || q?.id !== questionId || q.kind !== 'question' || q.is_handoff !== undefined && q.is_handoff !== false
    || q.asker?.type !== 'agent' || !isId(q.asker?.id) || q.prompt !== request.prompt || q.context !== request.context
    || q.responder_scope !== 'direct' || q.target_user_id !== request.target_user_id || q.resolution_policy !== 'first'
    || q.results !== undefined && q.results !== null || q.text_input !== null || q.correlation_id !== request.correlation_id || q.reply_to !== null || hash(q.data) !== hash(request.data)
    || (q.room_code ?? q.room?.code) !== room || q.room_code !== undefined && q.room_code !== room
    || q.room !== undefined && q.room?.code !== room || !['pending', 'answered', 'expired', 'cancelled'].includes(q.state)
    || !Array.isArray(q.options) || q.options.length !== request.options.length
    || q.options.some((option, index) => option?.value !== request.options[index].value || option?.label !== request.options[index].label || option?.primary !== undefined && option.primary !== false || option?.destructive !== undefined && option.destructive !== false)) throw new Error('Question does not match the saved task, room, or service owner.');
  const observation = { createdAt: iso(q.created_at), expiresAt: iso(q.expires_at), checkedAt: iso(checkedAt), askerId: q.asker.id,
    resolvedAt: q.resolved_at === null ? null : iso(q.resolved_at), answer: null };
  let status = q.state === 'answered' ? 'invalid_answer' : q.state;
  if (q.state !== 'answered' && q.answer !== null) throw new Error('Unresolved Question includes an unexpected answer.');
  if (q.state === 'answered') {
    const answer = q.answer;
    try {
      if (!answer || answer.text !== null || answer.responder?.id !== request.target_user_id || !request.options.some(option => option.value === answer.value && option.label === answer.label)) throw new Error('Invalid button answer.');
      observation.answer = { value: answer.value, label: answer.label, responderId: answer.responder.id, answeredAt: iso(answer.answered_at) };
      validateObservation(observation, 'answered', request); status = 'answered';
    } catch { observation.answer = null; }
  }
  validateObservation(observation, status, request);
  return { status, observation };
}

export function assertParticipantRoom(rooms, room, participantId) {
  if (!Array.isArray(rooms) || rooms.length > 1000) throw new Error('Invalid room inventory.');
  const matches = rooms.filter((item) => item?.invite_code === room), selected = matches[0];
  if (matches.length !== 1 || selected.type !== 'standard' || selected.is_public !== false || !Array.isArray(selected.members)
    || selected.members.length > 1000 || !selected.members.some((member) => member?.user_id === participantId)) throw new Error('Use a granted standard private room containing the named participant.');
}
