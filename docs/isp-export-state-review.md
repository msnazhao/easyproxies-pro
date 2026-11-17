# ISP export state review

## Confirmed defects and fixes

Repeated pool registration replaced the entire `NodeInfo` while leaving the entry's metadata completion flags unchanged. A regression that enriches a healthy SS node with score 58 and registers its unchanged connection again reproduced the loss of exit IP, network type and AbuseIPDB data. Registration now compares stable connection identities, retains measured fields for the same node, applies current static settings, and recomputes the display name. Reusing a tag for another connection creates a fresh entry so old callbacks cannot populate the replacement.

An in-flight metadata lookup previously wrote its full saved `NodeInfo` back after completion. A second regression reproduced a rename, URI fragment and port update being reverted by that write. Completion now publishes only measured fields and formats the name using the current original name. Real-use notifications received during an in-flight lookup receive a follow-up pass using cached results, without spending another successful AbuseIPDB request.

## Limits of the proposed diagnosis

If the same snapshot, URL filters and output format are used, adding only `n=isp` narrows results by `network_type`. Separate HTTP requests are not an atomic comparison: health, blacklist status and asynchronous metadata completion can change between them.

The automatic `ISP|` prefix and network type are computed from the same classification and published under one entry lock. A basic registration overwrites the name as well as the type, so that overwrite alone does not prove a persistent `ISP|` name with an empty type. Such a name can also be part of imported configuration or an earlier UI snapshot. The registration bug is confirmed; identifying it as the cause of a particular deployed omission still requires that node's runtime snapshot or a lifecycle reproduction.

Pools register members in both construction and member initialization. These normally run before the centrally started initial probe; their existence does not establish that registration always occurs after enrichment. Tests explicitly exercise a late registration and an in-flight completion.

Unknown usage categories are not automatically residential/ISP. `Commercial` and `Organization` remain unknown; only surrounding whitespace and case are normalized. A composite category needs observed API evidence and an explicit mapping before it can be trusted. Subscription names are untrusted display text and never authorize `n=isp` membership.

## Verification

Regression tests cover late registration, renamed stable identities, tag reuse with old callbacks, in-flight static updates, pending classification, score 58 export, forged ISP prefixes and coalesced real-use events. Existing SS URI parsing/export tests cover score-independent export. The temporary omission of unclassified nodes from `n=isp` remains intentional; names and membership become available together after classification.
