# An injection, stage by stage

An earlier piece, [the model is not the system](model-is-not-system.md), argued that serious AI work has
become an arrangement rather than a single model, and closed on a vulnerability-research tool built that way. The
argument there was conceptual. This one does the opposite. It takes a single ordinary finding and follows it through
every stage, branching at each step into the full set of things the system can do with it. A shape is clearest in
what it does to one case.

Command injection is a good case to walk, because it is the plainest. It is the trick of slipping an extra
instruction into text a program hands to a shell to run: a filename field that, filled with the right punctuation,
stops being a filename and turns into a second command. The attack needs a shell call to ride into. Code that hands
nothing to a shell offers it nowhere to sit. That dependence on a specific operation being present is what makes the
class easy to trace through a pipeline that is, stage by stage, mostly an argument about whether the operation is
there and whether anything reaches it.

## Index: facts, before any model

The first stage reads the code with no model involved, function by function, and writes down what it finds. For a
call that runs a command it records a few things: whether a shell interprets the command line or the program is run
directly, whether the arguments arrive as a list or as one assembled string, and where the first argument came from.
That last fact has four possible shapes. A parameter named outright. A parameter woven into a larger string. A
constant the code wrote itself. Or a trail that goes cold, because the value arrived from a helper the
single-function reading cannot follow. Everything downstream leans on these few facts, so it is worth noticing how
modest they are: one pass over one function, recording sinks and the provenance of what flows into them, no more.

```
        Function
           │
           ▼
         Index
           │
           ├─ subprocess
           │    ├─ shell=True/False
           │    ├─ argv=list/string
           │    └─ arg_source
           │
           ├─ file_read
           ├─ file_write
           └─ dangerous_sink
```

## Hypothesise: a model proposes

The model sees the function and the facts written beside it, and proposes. For the case at hand it offers command
injection, with an assumption it claims is broken, an effect it expects, and a handful of concrete inputs to try.
The inputs are concrete on purpose: a schema rule rejects template tokens, so a suggested input of `<command>` or
`SOME_PLACEHOLDER` is turned away at the door, and only a testable string survives. A confidence is attached. The
status can only be proposed, never confirmed: a model is not allowed to mark its own work as established, by
construction rather than by request.

All the possibilities here are possibilities of volume and phrasing. The model may propose nothing, one finding, or
several. It may spell the same class a dozen ways. None of that is judged yet. Proposing is cheap, and the stage
treats it as cheap.

## Screen: where the class meets the facts

This is where command injection branches into everything the system can conclude about it, by setting the proposal
against the recorded facts. 

```
                 Hypothesis
                      │
                      ▼
              Matching sink?
                │        │
               No       Yes
                │        │
                ▼        ▼
         Unsupported   Mechanism contradicted?
                         │         │
                        Yes        No
                         │         │
                         ▼         ▼
                  Contradicted  arg_source
                                   │
                 ┌─────────────────┼────────────────┐
                 ▼                 ▼                ▼
            parameter      parameter-derived     unknown
                 │                 │                │
                 ▼                 ▼                ▼
             Grounded          Grounded           Unknown   
```

The possibilities are worth listing in full, because the distinctions between them are
the stage.

- A shell call that a controlled input reaches: grounded. Accepted at the model's confidence. This is the dangerous
  shape, the one the class was named for.
- A shell-free call that a controlled input reaches, where the proposed payload leans on shell punctuation, the
  semicolons and pipes and backticks: contradicted. With no shell to read them, that punctuation is just characters
  inside an argument. The path from input to call is real, but the mechanism proposed over it cannot fire. Dropped.
  This is the sharp case: a genuine input-to-call path, rejected not because the input is harmless but because the
  trick named for it has nowhere to act.
- A shell-free call, controlled input, and a payload that does not lean on shell punctuation: grounded, but as a
  quieter thing, argument injection rather than the shell variety. A different finding wearing the same word.
- A call whose argument is a constant the code wrote itself: contradicted. Nothing a caller controls reaches it.
- A call that is present, but reached through a helper the reading could not follow: unknown. Kept, at a capped
  confidence, because losing a trail is the analysis reaching its limit, not proof that nothing flows.
- No command run anywhere in the function: unsupported. Dropped. The class has nothing to sit on.

Where several calls in one function disagree, the strongest claim wins, grounded over unknown over contradicted over
unsupported, so a limit on one call never poses as proof across the others. Only grounded and unknown go forward.
Contradicted and unsupported stop here, counted but not carried.

```
            Accepted hypotheses
                    │
                    ▼
               Synthesise
                    │
                    ▼
                 Execute
                    │
                    ▼
                 Verify
                    │
                    ▼
                 Report
```

## Synthesise: what the payload stage can build, and on what it depends

Only survivors reach this stage, which is the first place the design pays for the screen: a contradicted or
unsupported command injection never costs a payload, never costs a run. What arrives is grounded or unknown, and the
model is asked to turn the hypothesis's few suggested inputs into a richer set.

What it can build is a spread of variants, each labelled by kind: a baseline, encoded forms, oversized forms,
unicode confusables, nested structures, polyglots. Each payload carries a one-line note on why that variant might
take a different path through the code. As everywhere else, the model proposes inputs only and is told in as many
words not to assess whether any of them works. Breadth is its job; judgement is not.

For command injection specifically there is one more move, and it is what later makes the verdict clean. Each
payload is given a unique unguessable marker, and the payload is rewritten to also echo that marker back. The
reasoning is worth following: if the injection genuinely runs through a shell, the marker turns up in the output,
and a later stage can confirm by finding a string rather than inferring from a crash. The cleanest evidence that an
injection fired is the injection printing something only it could have printed.

That move depends on something narrow, which is worth naming because it has teeth. The marker is attached only when
the class name normalises to exactly the expected one. A finding the model spelled as plain command injection gets
the marker. A finding it dressed up as command injection via shell metacharacters does not, because the dressed-up
name does not normalise to the marked one, and so it goes forward as an ordinary payload without the clean signal.
The same recall that makes a model name things many ways has a small cost here, paid in lost precision rather than
lost safety.

One more possibility lives in this stage: it can produce nothing. A model that returns no usable payloads leaves
even a well-grounded hypothesis with nothing to run, and it drops out of the flow here, not for being wrong but for
being unrendered.

## Execute: the only witness to fact

Each payload is run against its target function inside an isolated environment, the one part of the system entitled
to settle whether something is true. No network, a read-only root, a timeout, the function called with the payload
as its input. What returns is an observation: an exit code, whatever was printed, whatever went to the error
stream, whether it ran out of time, and the marker if one was set. Running the payload moves the hypothesis from
proposed to tested.

The possibilities are few and flat. It ran, and there is an observation. It could not be set up, the target missing
or unreadable, and it is skipped. It hung, and the hang is recorded as a fact rather than smoothed over. Nothing
here interprets; interpretation is the next stage, kept separate on purpose.

## Verify: a comparator, not a judge

```
                      Observation
                            │
                            ▼
                    Verification rules
                            │
                ┌───────────┼───────────┐
                ▼           ▼           ▼
            Marker      Expected     Timeout
             found       effect       hit
                │           │           │
                ▼           ▼           ▼
             Confirmed  Confirmed   Confirmed
   
        
                Any other outcome
                        │
                        ▼
                     Refuted
```

The verdict is decided by fixed rules comparing the observation to the hypothesis, with no model consulted. A
timeout reads as confirmed, since for some classes running forever is the effect. A marker that was set and is
found in the output reads as confirmed, and for command injection this is the clean win, the injected echo having
run. A marker that was set and is absent reads the other way: the injection did not fire, refuted for want of
confirming evidence. With no marker, a non-zero exit reads as confirmed, a crash being something, and the expected
effect appearing in the output reads as confirmed too. Anything else is refuted. A confirmation, once written, is
never overwritten by a later refute.

After the verdict, a lookup by weakness category attaches any matching public vulnerability identifiers, as a label
beside the finding, without touching whether it was confirmed. The label describes; it does not decide.

This stage is where the rule that a model cannot be the judge actually lives. The only places a verdict is written
are the two transitions in this one file, tested to confirmed and tested to refuted, and a reader checking the claim
can find exactly those two lines. The discipline is in the layout, not in a promise.

## Report: every form a reader can find

A report is assembled from the verdicts, and it comes in a small number of forms. Walking the command-injection case
through each is the quickest way to read one.

A header, always: a generation time and a one-line tally, so many confirmed, so many refuted, so many skipped.

A screening paragraph, when a screen ran: how many proposals were grounded, how many kept as unknown at a capped
prior, and how many were rejected before any execution, split into those contradicted by the facts and those with no
matching operation at all. This is the only place the dropped majority appears. A command injection rejected at the
screen shows up here as part of a count, not as a finding, which is the honest treatment: the discarded are tallied,
not vanished.

A confirmed finding, when one survives all the way: a heading of location and class; the assumption it broke; the
effect expected; an evidence line, which for this case reads as the marker found in the output; a grounding line
naming the grounding state, why it landed there, and the confidence, full for a grounded finding; any attached vulnerability
identifiers; a reference to the stored observation, so the raw run can be retrieved; and a provenance line, the
chain of what happened to this hypothesis from a model's proposal through tested to confirmed, each link recorded
rather than summarised.

A refuted hypothesis, when one ran and did not fire: location and class; a reason line, which for a missed injection
reads as no confirming evidence; the same grounding line; the provenance. Read closely, a grounded-and-refuted
command injection says something precise: the path was real, the payload ran, and nothing happened. An
unknown-and-refuted one carries its capped confidence in the grounding line, a standing reminder that it was a maybe
from the outset and was treated as one.

And an empty form: no confirmed findings. This is the ordinary majority outcome, not a malfunction, and it was the
result the one time the tool was turned on its own quiet code, where a great deal of confident naming met almost
nothing for any of it to act on.

## Why one case is enough

A single finding shows the structure better than a diagram, because every branch the system can take is a branch it
takes on something. Command injection grounded and confirmed, grounded and refuted, kept as an unknown and never
fired, contradicted because the shell was not there, unsupported because the command was not there: each is a real
exit, and a report is mostly an account of which exit was reached and on what evidence. The arrangement is not the
model. It is what these stages do to one ordinary claim on its way from a guess to a line in a report, or to a
number in a count of the things that never got that far.

```
                              Command injection
                                      │
                                      ▼
                                 Hypothesise
                                      │
                                      ▼
                                   Screen
              ┌───────────────┬───────────────┬───────────────┐
              ▼               ▼               ▼               ▼
          Grounded         Unknown      Contradicted     Unsupported
              │               │
              ▼               ▼
         Synthesise       Synthesise
              │               │
              ▼               ▼
          Execute          Execute
              │               │
              ▼               ▼
           Verify          Verify
              │               │
           ┌──┴──┐        ┌───┴───┐
           ▼     ▼        ▼       ▼
    Confirmed Refuted  Confirmed Refuted
```
