# Recall is not evidence

An earlier piece, [the model is not the system](model-is-not-system.md), argued that serious AI work had
stopped being one capable model and become an arrangement: a generator proposes, something checks, execution
decides, an audit layer remembers. A closing example was a vulnerability-research tool built on that separation.
Enough has changed in it since to be worth a second look, less for the engineering than for what the engineering
reveals about where arrangements of this kind tend to grow next.

What grew is a part that sits between the proposing and the testing, and it earns its place by asking a question
duller than a model is inclined to ask.

```

                 Static analysis
                       │
                       ▼
                 Security facts
                       │
                       ▼
                 Hypothesise
                  (model)
                       │
                  hypotheses
                       │
                       ▼
                    Screen
              "Is this grounded?"
            ┌──────────┼──────────┐
            ▼          ▼          ▼
        Accept      Penalise    Reject
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

## An attack class is not present because it can be named

The earlier piece put one observation at its hinge: a reasoning trace is not trustworthy because it exists. A
fluent explanation can be wrong, so an explanation needs evaluating rather than reading. A close cousin of that
observation turned up in practice, and is worth stating in the same shape: an attack class is not present in a piece
of code because a model can name it.

A model that has read the literature, which is all of them now, knows every category of vulnerability by heart.
Shown a fragment of code, it will offer command injection, code injection, unsafe deserialisation, path traversal,
and a dozen more, fluently and in order, the way a keen student lists everything that might be on the exam. The
naming is recall. Recall is cheap, broad, and almost entirely uninformed by whether the named thing has anywhere in
this particular fragment to happen. A model can propose command injection against code that runs no commands with
the same confidence it brings to code that does, because the proposal is drawn from what the category looks like,
not from what the code in front of it contains.

Command injection is the plainest case to picture. It is the trick of slipping an extra instruction into text a
program hands to a shell to run: a filename field that, filled with the right punctuation, stops being a filename
and becomes a second command. The attack needs a shell call to ride into. Code that hands nothing to a shell offers
it nowhere to sit, however confidently the category is named over it. The rest of the catalogue runs the same way.
Unsafe deserialisation needs something that rebuilds an object out of bytes. Path traversal needs a file opened by a
name a caller can bend. A class is a shape, and a shape needs a matching operation somewhere in the code before it
is anything more than a word.

```
    Attack class            Needs somewhere to land
    
    Command injection   ───► subprocess / shell
    Path traversal      ───► file read or write
    Code execution      ───► eval / exec / compile
    Deserialisation     ───► pickle / yaml / marshal
    
    No matching operation
            │
            ▼
    The class is only a name.
```

## An organ between propose and test

The new part reads facts that a plain, non-AI pass has already pulled out of the code, with no model involved:
every place it does one of those dangerous things, runs a command, opens a file, evaluates a string, hands data to
something that deserialises. Those are the matching operations the classes need, the places where a shape could have
somewhere to sit. And, for each of them, where the value arriving there came from, as far as a single reading of one
function can tell. That is the other half of the question: not just whether a shell call is present, but whether
anything a caller controls reaches it. Then, for each thing the model proposed, it asks whether the code grounds it.
Does an operation of the named kind exist, and does an input a caller controls reach it. Not whether an attack would
work, which only running it can settle, but whether there is anywhere for it to work at all.

Four answers come back, and they are kept in plain language because the distinctions between them are where the
honesty lives.

- Grounded: an input reaches an operation of the named kind. Carry it forward.
- Unknown: an operation of the named kind is present, but the trail from the input goes cold before reaching it,
  because the analysis is reading one function and the value arrives from somewhere it cannot follow. Carry it
  forward, at a lowered prior.
- Contradicted: the facts rule the proposed mechanism out. Drop it.
- Unsupported: nothing of the named kind is anywhere in the fragment. Drop it.

```
             Hypothesis
                  │
                  ▼
        Matching operation?
            │          │
           No         Yes
            │          │
            ▼          ▼
     Unsupported   Mechanism
                   impossible?
                    │      │
                   Yes     No
                    │      │
                    ▼      ▼
             Contradicted  Input reaches sink?
                              │        │
                             Yes      Unknown
                              │
                              ▼
                          Grounded
```

## A line held between two of them

Most of the work in that list is a single refusal: not to treat unknown as the same as safe. 

```
              Trail reaches sink?
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
         Yes             Trail lost
          │                   │
          ▼                   ▼
     Grounded             Unknown
    
    Unknown ≠ Safe
    Unknown = Analysis stopped
```

When the analysis
loses the trail, it has reached its own limit, not proved an input harmless. Collapsing those two would be the
comfortable error, because it would let a system look more decisive than it is and quietly discard the cases it
could not follow. Instead a case it could not follow is kept, marked as not-followed, and held at a capped
confidence rather than waved through or thrown away. The same restraint applies one level up: a class the system has
no check for is not silently rejected for the offence of being unfamiliar. It is kept, flagged as unassessed, at the
same capped prior. A novel attack penalised can be recovered. A novel attack discarded is silence.

## What changed in the arrangement

In the language of the earlier piece, the arrangement gained an organ that does triage before the expensive
witness. Execution is still the only thing that turns a finding from proposed to confirmed, and it is still the
costly step: standing up an isolated environment, running code, watching what happens. Putting a cheap structural
check ahead of it means the expensive witness is not called to rule on proposals that had nowhere to land in the
first place. That is a saving, but the saving is not the interesting part.

The interesting part is that the check makes a model's enthusiasm legible. Before, a flood of plausible category
names went downstream and the cost of sorting them was paid later, or not at all. Now the flood meets a question it
cannot bluff, and what passes is countable. How much of what a model proposed had anywhere to go becomes a number
rather than an impression. A system that can count how often its generator was talking into the air is in a
different position from one that cannot.

## A first run, on its own code

The tool was pointed at its own pipeline code, which is a fair test and a slightly unsporting one: the code that
decides what counts as a vulnerability is also code that does very little a vulnerability could use. It shells out
nothing, evaluates nothing, deserialises nothing it does not trust. So it is a body of code with almost no attack
surface, handed to a model that knows every attack by name.

The model proposed 61 findings across 44 functions, and reached for roughly 50 different labels to do it: command
injection more than once and in more than one spelling, code injection in eight, unsafe deserialisation in four. The
check found that 60 of the 61 had nowhere in the code to land. 

```
    44 functions
         │
         ▼
    61 hypotheses
         │
         ├──────────────────────────────┐
         ▼                              ▼
    60 Unsupported                 1 Unknown
       Rejected                 (0.35 confidence)
                                        │
                                        ▼
                             No concrete payload
                                        │
                                        ▼
                               No execution
```

One survived, and survived honestly: not because
anything grounded it, but because it named a category the system has no check for, so it was kept as an unassessed
maybe rather than dropped. Nothing in that run reached the stage of being built into a test and run, because the one
survivor could not be turned into a concrete payload. Which is the correct outcome for code that does nothing
dangerous: a great deal of confident naming, almost none of it with a place to happen, and a system that noticed.

A run against code with real surface, command-running, file-handling, the parsing of untrusted input, would put the
other outcomes to work, and is the next thing worth doing. One quiet body of code is a single data point, not a
verdict on anything.

## What is being measured, and to what end

```
                        Measurements
    
                 ┌──────────┴──────────┐
                 ▼                     ▼
    
           Metric 1                    Metric 2
        
        Extractor coverage        Screen outcomes
        
        "What can we trace?"    "What happened to the
                                 model's proposals?"
        
        Model-free               Model-dependent
        
        Measures extractor       Measures arrangement
```

Two numbers are kept, and kept deliberately apart, because they answer different questions and reading them together
would blur both.

First, coverage of the analysis itself. Of the places in a body of code where an input could reach a dangerous
operation, how many can the plain non-AI pass actually trace back to an input it can name, rather than losing the
trail. This number involves no model at all. Its purpose is to say whether the fact-extraction is getting better at
following data through code. Its use is comparative and only comparative: measured against a fixed body of code, a
falling count of lost trails is one honest sign the extractor improved, as against the code happening to be easier
this time. On the run above the number was unflattering and clear: of the few places worth tracing, none could be
followed to a named input, because the data arrived through indirection a single-function reading does not cross.
That is not a failure to hide, it is the next thing to fix, named precisely.

Second, the spread of outcomes. Of everything a model proposed, how much came back grounded, unknown, contradicted,
or unsupported. Its purpose is to say whether the check is doing real work, removing things, or merely lowering
confidence on everything and removing nothing. Its use carries a condition: the spread moves with both the analysis
underneath it and the model doing the proposing, so a comparison across runs holds only where the body of code is
fixed and the model is fixed, with any change to either noted beside the number rather than buried in it.

What the two are for, together, is to keep the arrangement falsifiable. The risk in a design like this is not that a
component fails loudly. It is that a component sits in the pipeline producing reassuring output while doing nothing:
a check that never rejects, a coverage number that never moves. Counts make that visible. They are counts and not
scores on purpose, in that they do not rank findings, weight them, or pass judgement on the code. They report what
happened, so that drift, the slow slide of a check into theatre, has somewhere to show up.

The plan is the dull one the metrics imply: keep a fixed body of code, re-measure as the parts change, and watch
whether the lost-trail count falls and whether the spread of outcomes stays earned. A measurement layer that scored
these numbers, or told an observer what to feel about them, would be one more confident voice in a system whose
whole design is an argument against confident voices. Counting is enough. The aim of the arrangement was never to
sound sure. It was to arrange things so that being wrong leaves a mark.
