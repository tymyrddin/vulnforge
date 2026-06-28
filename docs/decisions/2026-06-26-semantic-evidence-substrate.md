# Facts as a semantic substrate, and the OT/ICS direction

## Context

The grounding work changed what vulnforge is. The pipeline below the extractor
is phrased in semantics, not syntax: it asks whether a source can influence a
sink, not what language expressed either. That property is worth more in embedded
and industrial code than in web code, where for the web the language tends to
dominate and for firmware the semantics do. A watchdog-disable register write is
the same fact whether it was reached through C, Rust, ARM Thumb, AVR, or a lifted
binary. Vulnerability discovery is one reading of such a fact; safety analysis,
compliance evidence, and firmware assurance are others, asking different
questions of the same fact.

The direction under consideration is OT/ICS code, prioritised for European
industrial systems: ARM Cortex-M first (STMicroelectronics STM32, then NXP and
Infineon Cortex-M families), then Infineon AURIX/TriCore, then IEC 61131-3
Structured Text ahead of ladder logic. The question this record settles is what
stays fixed as the front ends multiply, and what the next build step is.

## Decision

The invariant under all five calls: the extractor emits semantics, not findings.
It emits neither vulnerabilities, nor safety issues, nor compliance violations,
but observable semantic facts; everything downstream is interpretation.

Five calls are locked.

One fact substrate, only lenses, not parallel types. A single Fact carries an
operation, a target, provenance, and other domain-specific attributes. Security,
safety, and compliance are questions asked of those facts, not classifications
stored inside them. The vulnerability reading asks whether
attacker-controlled input can reach an operation; the safety reading asks whether
an operation occurred on a safety-critical resource, with no taint predicate
required; the compliance reading asks whether it breaches a named policy clause.
A safety-relevant state change (watchdog disabled, secure boot off, interlock
bypassed) decomposes into the existing shape: operation, target as a new sink
class, influence as an optional predicate. Naming a new operation, target, or
predicate extends the vocabulary, not a new type for every downstream stage to
learn.

The same predicate discipline on the output side. Fact and Observation are
siblings, not parent and child: a Fact is a semantic object at the input end, an
Observation is a semantic object at the output end, and both are queried through
predicates. An Observation is observed state, and an Outcome is a predicate over
it. Hypothesise predicts a state predicate, execute produces observed state,
verify evaluates the predicate against the state. This keeps verify
backend-neutral and folds the closed-enum `expected_outcome` (Move 2 in
[../roadmap/verdict-pipeline.md](../roadmap/verdict-pipeline.md)) into the same
shape: Outcome becomes a predicate vocabulary, not a Python-specific enum. Input
facts and output observations are the two ends of one pipeline, each queried
through predicates; the pipeline asserts a predicate over state, grounds it at
the input, verifies it at the output.

Plug-in per layer, with execute and verify named as the hard seam. Index takes a
language plug-in, screen a predicate-vocabulary plug-in, execute an
execution-backend plug-in, verify an observation plug-in. Orchestration and the
inter-stage contracts (Fact, Observation, the predicate relation) stay fixed.
Index and screen take the plug-in cleanly. Execute and verify carry the
architecture-specific weight, because payload delivery and observation shape
differ per backend: a Python payload is function arguments, a firmware stimulus
is a register write, a frame injection, or an interrupt; a Python observation is
exit and sanitiser state, a firmware observation is peripheral and memory state.

IR is a dependency-inversion trade with an expressiveness ceiling. Reasoning over
a third-party IR (Ghidra P-code, VEX, LLVM IR) makes that IR's semantics the
substrate. The cost is not ownership alone; it is the ceiling on what a fact can
express. A lifter that normalises a peripheral write into a generic memory store
discards which peripheral before the ontology sees it, and a safety fact needs
that distinction where a CWE finding often does not. The first architecture uses
a native Cortex-M Thumb decoder, which keeps control over what survives the front
end. Binary lifting in general is deferred.

Thin vertical before ontology. The fact ontology, the IR layer, and the consumer
abstraction get designed against a confirmation that fired, not against a
diagram. The next build is one vertical end to end: an STM32 firmware image with
a watchdog-disable, a Thumb decoder producing slices, one predicate (watchdog
control register written to disable), executed under an emulator (Renode models
the STM32 peripherals), observing the watchdog disabled, reaching CONFIRMED. This
produces the first positive CONFIRMED verdict on real surface (the only prior
end-to-end run is `stages/`, which has almost no sinks, so no CONFIRMED verdict
has landed on a meaningful artefact), and validates the semantic-substrate thesis
at the same time. The semantic-evidence-engine framing, facts as a stable
interface with vulnerability discovery as the first of several consumers, is the
navigation target, not the next build. A neutral fact interface
cannot be designed from one consumer; with only the vulnerability pipeline
pulling, anything called neutral stays vulnerability-shaped until a second
consumer disagrees. The interface is demonstrated, not asserted, the first time a
safety consumer reads the same watchdog fact the vulnerability pipeline produced
and needs nothing added. That second consumer is one step past the vertical and
is the cheapest test of the thesis.

## Why

The substrate-and-lens shape keeps the reasoning machinery stable while the front
ends and consumers multiply. A separate type per concern would force every stage
to learn each concern; one substrate with vocabularies confines change to the
vocabularies. Applying the same shape to observations is what lets verify stay a
deterministic comparator across execution backends instead of growing a
backend-specific judge, which would reopen the AI-judge question settled in
[2026-05-12-execution-is-authority.md](2026-05-12-execution-is-authority.md).

Naming execute and verify as the hard seam sets expectations before the
abstraction is promised wider than it holds. The IR stance records why a native
decoder is worth its cost on the first architecture: the expressiveness ceiling
of a borrowed IR is a blind spot the safety ontology cannot afford.

Thin-vertical-first applies the project's standing discipline to its own roadmap.
The architecture is proven when it produces a confirmation from the real
position, not when a design reads well. The platform framing is powerful and
easier to explain than firmware analysis, which is precisely why it is the more
dangerous thing to build first: it invites abstraction ahead of evidence. The
brake is to make one watchdog fact reach CONFIRMED, then have a second consumer
read it, before generalising. The build order is tracked in
[../roadmap/ot-ics-direction.md](../roadmap/ot-ics-direction.md).