# PingRoom rule shadowing

Audit an existing ordered rule policy after a named service owner declares whether the first or last matching rule determines the result. Code enumerates a finite request domain and reports which rules take effect, which are shadowed, and where opposing actions overlap.

The example is a fictional library with staff, visitors, documents and read/edit actions. This starter produces a local diagnostic. It never queries a service, changes access, removes rules or deploys a policy.

## Try it offline

Choose **Use this template**, clone your copy, and use Node.js 22 or newer on macOS or Linux:

```sh
npm ci
npm test
npm run demo
```

The three demos use first-match, last-match and Unknown answers through the real pinned SDK with a local mock transport. They require no account, credentials or network after installation. Live phone delivery is not tested.

`@pingroom/sdk` 0.8.0 and its lockfile are pinned. `.npmrc` requests exact saves and a 14-day minimum release age where npm supports it. GitHub Actions checks installation, tests and demos on Node 22 and 24 with actions pinned to commits.

## Define the policy and request domain

```sh
cp examples/policy.json policy.json
cp config.example.json config.json
npm run validate
```

Edit the copied `policy.json` before starting. Validation prints the canonical policy and resolution task without contacting PingRoom. Inputs contain:

- `policyId`, `title`, `context`: identify the policy and explain which existing service's resolution behavior the owner should declare. Limits are 32, 32 and 80 UTF-16 units.
- `dimensions`: exactly `principals`, `resources` and `actions`. Each contains 1–4 entries with an `id` and `label`; all combinations form the request domain, up to 64 requests.
- `rules`: 1–8 ordered entries, each with an `id`, `label`, `decision` (`allow` or `deny`) and `match`.
- `match`: a nonempty subset of IDs for each dimension. A rule matches only when all three request values belong to their corresponding subsets.
- `defaultDecision`: exactly `deny`, applied when no rule matches.

IDs begin with a lowercase letter and contain lowercase letters, digits, `_` or `-`. Domain and rule IDs allow 12 characters; `policyId` allows 32. Rule IDs are unique, as are value IDs within each dimension. Reserved object names are rejected for domain and rule IDs. Labels allow 24 units for domain values and 40 for rules. Metadata must be trimmed, nonempty, well-formed and free of controls, formatting characters and line breaks. Extra fields, empty or duplicate match values, unknown IDs and sparse arrays are rejected. The input file limit is 64 KiB.

**Rule order is part of the policy.** Reordering rules changes its identity and can change the result. Domain entries and rule match subsets sort by ID because their input order has no meaning.

There are no wildcard strings, network ranges, executable conditions, group inheritance or implicit principals. To model “all,” list every supplied value for that dimension. Every combination of supplied values is considered possible; correlated or impossible combinations are not inferred.

## Connect and declare resolution behavior

Install [PingRoom](https://pingroom.io/i), then:

```sh
npm run connect
npm run inspect
```

Approve the displayed connection and grant the intended standard private room containing the service owner. Verify the person in the app, then put their exact member UUID and descriptive label in `config.json`; a matching display name is not enough. The connection needs room access and Question creation/read permissions.

For an existing granted robot credential, copy `.env.example` to `.env` and set both `PINGROOM_TOKEN` and the 12-character `PINGROOM_ROOM`. A partial or blank environment pair fails rather than borrowing missing values from saved credentials. Pairing credentials stay in ignored `.pingroom/`.

```sh
npm start
# After the owner answers in PingRoom:
npm start
```

The Question shows the policy context, ordered rule IDs and a short snapshot reference. Review the full local preview before answering. Use non-sensitive identifiers and metadata. Choose **First matching rule**, **Last matching rule**, or **Unknown** based on the existing service's documented behavior.

The workflow uses one Question with a 15-minute lifetime. Each invocation creates it once or reads its existing response once. There is no automatic polling or replacement. The declaration concerns your rule policy; PingRoom's own Question uses ordinary first-answer resolution in both cases.

Unknown, missing, expired, cancelled, malformed or misattributed answers block the complete audit. The application validates the original request, owner, room, asking registration, input, options and timestamps before accepting evidence.

## Read and export the audit

```sh
npm run status
npm run report
npm run export
```

These commands are local. `report` also saves `.audit/report.json`, including partial evidence. `export` writes `.audit/analysis.json` only after a known valid declaration. The output includes the source policy, hashes, attributed answer and `analysis`:

- `requests`: every request in ASCII principal/resource/action ID order, its matched rule IDs, selected winner or null default, and allow/deny result. It also includes the modeled first- and last-match outcomes.
- `rules`: each rule's original one-based position; matching, effective and overridden counts; status (`unshadowed`, `partially_shadowed` or `never_effective`); and witness requests. `overriders` identifies the winning rules responsible, their counts and witnesses.
- `opposingActionOverlaps`: pairs of matching rules with different actions, their overlap size and a witness. These are findings, not automatic policy errors.
- `resolutionDifferences`: requests whose allow/deny result differs between first- and last-match semantics. This can be empty even when a middle rule opposes both endpoint rules.
- Coverage totals: matched/default request counts and allow/deny counts. Effective rule counts plus default coverage must equal the domain size.

Same-action rules can still shadow one another. Several narrow rules can jointly shadow a broad rule even when no single earlier/later rule covers it. A completely shadowed rule has no selected effect **within this supplied domain and resolution policy**. That does not establish that deleting it is safe in a real service or outside the modeled domain. No removal recommendation or executable configuration is generated.

Complete audits containing shadowing or overlaps export successfully. Run commands exit `0` for a complete result, `1` for errors, `2` for incomplete/failed answers, `3` for pending/ready/interrupted and `4` for uncertain creation. Successful offline reports exit `0` even when their contents remain incomplete; inspect `status` and nullable `analysis`.

## Recovery and adaptation

Preserve `.audit/` after a lost creation response. Use `npm run find-id`, then `npm run recover -- QUESTION_UUID` for the exact original Question. An empty bounded search does not prove creation failed. Never delete state to force a resend.

Pairing preserves its pending bearer/session. Resume a known pending pairing with `npm run connect`. For uncertain or expired pairing, inspect Connected Agents and resolve or revoke the old registration before archiving pending state. Remove a stale lock only after confirming its process stopped.

Keep inputs, configuration, room and credentials fixed during a session. Resolve uncertain sends before archiving a session for a changed policy. State and exports use bounded reads, a process lock, atomic writes and private file/directory modes. Local hashes detect inconsistency; they are not independently signed history.

Adapt an upstream policy exporter to the explicit finite schema, then consume the JSON audit in your review process. Real inputs, credentials and generated files are ignored by Git. Tests compare 11,664 small policy/resolution cases with an independent set-subtraction oracle and cover maximum output, SDK recovery, pairing and real CLI subprocesses. MIT licensed.
