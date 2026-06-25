# The model is not the system

The instinctive picture of an AI system is a single model producing answers. Input goes in, output comes out, and the
only interesting question is how good the model is. That picture is becoming a poor description of how serious AI work
is now being done.

What is actually being built, in the systems that get pointed at when people talk about reasoning, is closer to a small
bureaucracy, though often an ad hoc one assembled per query rather than a fixed organisation.

- A generator proposes a candidate answer.
- A separate verifier examines whether the answer is consistent with what the generator was supposed to be reasoning
  about.
- A judge evaluates not the answer but the explanation, asking whether the rationale would hold up if read closely.
- An orchestrator decides which subsystem to invoke when.
- A retriever pulls in context the generator did not have.
- A symbolic checker confirms that what looks correct actually parses, type-checks, or executes.
- An execution environment runs the code the reasoning trace claimed would work.
- An audit layer keeps records of every step, so that disagreement can be analysed afterwards rather than waved at in
  the moment.

Each of these is a distinct role, though the role can be implemented by a separate model, a repeated prompt to the same
model, or heuristic glue code, depending on system design and constraints.

Picture a committee where one chair quietly wears three hats in sequence, another is on loan from elsewhere, and a
third turns out, on close inspection, to be a stack of conditional statements in a trenchcoat.

The field seems to have moved toward this arrangement, and not for aesthetic reasons. Larger and larger monolithic
models, asked to do all of these things at once, continued to be unreliable in specific and reproducible ways. A model
would solve a maths problem correctly while describing a different solution. A model would cite a paper that did not
exist, with an author who did not exist, in a venue that did. A model would write code containing a subtle bug while
explaining in detail how the code handled the exact case that triggered the bug, with the unflappable confidence of a
tour guide who has never set foot in the building.

A model that produces an answer can be wrong. A model that produces an answer plus a confident explanation of why the
answer is right can be wrong in a more damaging way, because the explanation tends to insulate the answer from
scrutiny. The remedy that emerged, after several years of insisting that the next bigger model would surely fix this,
was to split the work.

## The pattern looks familiar

```
         Institutions solving the same problem

Research     Courts     Finance     Engineering      AI
────────     ──────     ───────     ───────────      ──
Peer review  Adversary  Separation  Independent      Verifier
             review     of duties   verification

                         ▼

               Reliable output despite
                unreliable reasoning
```

This division of labour, looked at from a slight distance, is recognisable. It resembles the way humans have always
handled cognition they could not fully trust.

Peer review exists because a single researcher's claim about their own work is insufficient. Adversarial review, the
kind that goes on in courts, exists because the testimony of an interested witness needs an interested opponent.
Independent verification exists because measurement instruments drift, sometimes silently. Audit trails exist because
nobody can vouch for what they did six months ago without records. Separation of duties exists because anyone allowed
both to authorise and to execute a transaction will, sooner or later, do something inadvisable.

These are not features of any particular institution. They are structural elements that institutions have tended to converge on,
across cultures and centuries, for managing the specific problem of unreliable cognition that nonetheless needs to
produce reliable output. The instruments are familiar because the problem is old.

What is new is the recognition that AI systems have the same problem, and that the same general shape of solution may
apply. The analogy is imperfect, but it captures the way responsibility for an output ends up distributed across
components rather than located in one of them.

## A reasoning trace is not trustworthy because it exists

```
      Model output
        
        Question
           │
           ▼
        Reasoning trace
           │
           ▼
        Answer
        
        
     Evaluation pipeline
        
        Question
           │
           ▼
        Reasoning trace
           │
           ▼
        Evaluation
           │
           ├── logical?
           ├── grounded?
           ├── calibrated?
           ├── internally consistent?
           └── supports conclusion?
           │
           ▼
        Accepted output
```

A pivot point is a realisation that has been arriving slowly across multiple research lines. A reasoning trace, the
step-by-step explanation an AI system produces alongside its answer, is not inherently trustworthy. It can be fluent,
plausible, internally consistent, and wrong. It can resemble reasoning without containing the deductive structure that
makes reasoning correct.

This sounds obvious once stated. It took the field some time to absorb, because for several years the prevailing
assumption was that asking a model to "show its work" was itself a kind of solution: the explanation, once visible,
could be checked. In practice the explanations were often persuasive even when the answer was wrong, and human reviewers
without infinite patience would accept the explanation rather than reconstruct the reasoning from scratch. The same
property that made the trace useful, namely that it sounded like reasoning, was also what made it dangerous when wrong.

The response has been to start treating the trace itself as something requiring evaluation, not as the evaluation.
Several research programmes have moved in this direction over recent years, not as a coordinated effort but with enough
convergence that the alignment is hard to ignore.

[REVEAL](https://reveal-dataset.github.io/) is a benchmark, but a benchmark for verifiers rather than generators. The
dataset is designed such that the interesting question is not whether a model can produce a chain of reasoning, which by
now is routine, but whether a separate system can correctly tell whether a chain is sound. Sound versus unsound becomes
the unit of analysis, displacing correct versus incorrect.

[ReCEval](https://arxiv.org/abs/2304.10703) treats a
reasoning chain as a sequence of dependent steps and evaluates each step on three axes: whether the step correctly uses
information from its premises, whether it follows logically from the steps that came before, and whether it actually
contributes information toward the conclusion. Three distinct failure modes that single-number evaluation would have
collapsed into "wrong answer".

[DIVERSE](https://arxiv.org/abs/2206.02336) introduced this kind of step-aware
verification earlier than the broader wave became visible. Its central move was to combine diverse sampled reasoning
chains with a verifier that scored each step, and to show that this combination outperformed both single-path
chain-of-thought and majority voting across the chains. The implicit argument was structural: the win came from
filtering the generator's outputs with a separate apparatus, not from a better generator. A newer wave of judge models
defines itself explicitly as judging rather than generating, with some refusing the role of primary answer source on
principle, on the grounds that doing both well requires different training and different incentives.

Each of these contributions is, viewed individually, a paper about a specific technique. Viewed together, they describe
the construction of an evaluation infrastructure that lives between the generator and the user. The trace is no longer
simply produced and read. It is produced, evaluated, scored, sometimes rewritten, and only then surfaced. What the user
sees is no longer the model's output. It is what the layers around the model allowed through.

## CORRECT in this frame

```
          One judgement becomes several
    
               "Is the model good?"
                        │
                        ▼
┌────────┬──────────┬──────────┬──────────┬──────────┐
│Verdict │Reasoning │Confidence│Grounding │Rationale │
│quality │ quality  │          │          │ quality  │
└────────┴──────────┴──────────┴──────────┴──────────┘
```

[CORRECT](https://arxiv.org/abs/2504.13474), a 2025 evaluation framework, fits squarely in this pattern. Its
contribution is the explicit separation of several things that earlier evaluations had quietly fused: prediction
quality, reasoning quality, trustworthiness assessment, contextual grounding, and the judgement of whether the rationale
is valid as a piece of reasoning. The same paper uses LLM-as-judge methods to evaluate the explanations the system
produces, which is the institutional move in microcosm. A different subsystem is doing the evaluation than the one doing
the generation, and the field has accepted that this might be the only way to evaluate honestly.

What previously sat as one box labelled "is the model good" becomes five distinct questions:

- Was the verdict correct?
- Was the reasoning chain logically sound, or did it skip steps that happen not to be needed in this particular case but
  would in another?
- Is the model's stated confidence calibrated, or does it produce equally confident outputs whether it has cause to be
  or not?
- Was the answer grounded in the supplied context, or did the model improvise on the basis of training-set associations?
- Does the rationale, read on its own as a piece of reasoning, actually support the conclusion it claims to support?

A tool can score well on the first while failing the second. A tool can be calibrated and
ungrounded at the same time. A tool can produce a logically sound trace that argues for a wrong conclusion. None of the
five answers is the model's own. All five are produced by evaluation infrastructure that sits outside the model being
evaluated, though in practice "outside" often means a different prompt of a similar model, which introduces a class of
its own problems (self-preference, verbosity bias, style bias) that the field is actively working out. The underlying
principle, of separating the evaluator from the thing evaluated, is close to the bare minimum a serious
evaluation discipline tends to require. The principle is being applied. The mechanics for applying it well are still under
construction.

## Intelligence as an arrangement

```
              Intelligence

            Not one component
  
                    │
                    ▼
            
               ┌─────────┐
               │Propose  │
               └────┬────┘
                    ▼
               ┌─────────┐
               │Contest  │
               └────┬────┘
                    ▼
               ┌─────────┐
               │Execute  │
               └────┬────┘
                    ▼
               ┌─────────┐
               │Remember │
               └─────────┘
```

What seems most consequential in this turn is not technical but conceptual.

For most of the deep learning era, the implicit story was that intelligence was a property of a single sufficiently
capable model. The scaling debates were arguments about how to make that model bigger or better trained, but they did
not contest the basic picture: one model, doing one thing very well, was the unit of analysis. The research programme
was to find the right architecture and feed it the right data.

A set of related approaches begins to question this picture. It suggests that what humans call intelligence is not,
structurally, the output of a single mind. It is the output of an arrangement. Subsystems propose, because something has
to. Subsystems contest, because what goes unchallenged drifts. Records survive the people who made them, because
tomorrow's reviewer will not be today's author. And the capacity to mark a question as unresolved is maintained, because
forcing a verdict on a question that has no answer is a failure mode that produces durable error. The single mind,
when examined closely, also turns out to be such an arrangement, just one whose subsystems are less visible because they
share a skull.

If that is the right picture, making any single subsystem larger or better trained yields diminishing returns once the
subsystem is reasonably good. The gains tend to come from improving the arrangement instead.

- A better-calibrated verifier catches errors that a bigger generator does not, because the relevant skill is
  recognising wrongness rather than avoiding it.
- A judge that is not responsible for generating the work it evaluates, produces evaluations that can be argued with,
  because the conflict of interest has been removed by construction.
- An escalation rule that flags uncertain cases for human review turns a confidently-wrong system into one that admits
  doubt at the right moments, which is sometimes the difference between a tool that is useful and a tool that is
  dangerous.
- An audit trail dense enough to reconstruct what failed converts errors into evidence rather than noise, and a system
  that learns from failure converges; one that does not, does not.

Underneath this is a quieter shift: uncertainty becomes something the system
can express rather than something it has to suppress to look confident. Which is, suspiciously, what modern AI reasoning
research increasingly looks like.

It is a rather unexpected destination for a field that, not long ago, was preoccupied with making transformers larger.

## Around the model, or inside it

```
                Design choices

Train inside model          Build around model

Arithmetic             │    Calculator
Citation recall        │    Citation checker
Reasoning quality      │    Verifier
Safety                 │    Output filter
Execution prediction   │    Sandbox

               Architecture is policy
```

The visible argument in much current AI commentary is about whether the next generation of models will or will not
exhibit some particular capability. The argument that does not get made as often, but probably does more to shape what
gets built, is about which problems are placed around the model rather than inside it.

Whether to train the model not to
hallucinate citations, or to put a citation-checker downstream. Whether to teach the model arithmetic, or to give it a
calculator. Whether to align the model against producing harmful output, or to filter its outputs in a separate pass.

Each of these is a real choice currently being made by different teams in different directions, and the choice
determines the shape of the product. A field that decides intelligence requires infrastructure will build different
products than a field that decides intelligence is a property of the model itself.

For projects building AI tooling for serious work, vulnerability research being one example, the practical implication
is that betting on one good model is increasingly the wrong bet. The bet that survives is on an arrangement.

- A generator proposes findings, because something has to.
- A verifier checks each proposal against constraints the generator was not asked to enforce, because the generator's
  own confidence is not evidence of anything other than confidence.
- A judge evaluates the rationale rather than the verdict, because a fluent wrong explanation is more dangerous than a
  wrong answer with no explanation at all.
- An execution environment runs whatever the trace claimed would work, because claims about code are cheap and running
  the code is not.
- An audit trail keeps records of all of it, because the failure mode worth debugging tomorrow is the one whose
  context was discarded today.

```
                The monolith

           ┌─────────────────────────┐
 Input ───▶│         Model           │───▶ Output
           └─────────────────────────┘


               The arrangement

               ┌──────────────┐
               │  Retriever   │
               └──────┬───────┘
                      │
                      ▼
           ┌─────────────────────────┐
           │       Generator         │
           └──────────┬──────────────┘
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
      Verifier      Judge     Symbolic check
          │           │           │
          └───────────┼───────────┘
                      ▼
                 Execution
                      │
                      ▼
                 Audit log
```

The interesting design work is no longer the model. It is the arrangement around the model.

Whether the field calls this "agentic architectures", "verifier-centric reasoning", "process supervision", or any of the
other current terms is largely a question of which subgroup is doing the naming. What they have in common is more
interesting than what divides them. They are all part of the same institutional turn, working out, by trial and error,
the same lesson that human cognition arrived at over centuries: scale produces capability, structure produces
reliability, and what serious work needs is mostly the second.

## A worked example

```
                  vulnforge
    
              ┌──────────────┐
              │ AI generator │
              └──────┬───────┘
                     ▼
              Schema validation
                     ▼
              Deterministic checks
                     ▼
                 Sandbox run
                     ▼
              Verified outcome
                     ▼
            Tamper evident audit
```

The argument above is conceptual. A concrete instance lives in [vulnforge](https://github.com/tymyrddin/vulnforge), a 
vulnerability-research tool built around a similar separation of roles. The AI proposes hypotheses; deterministic 
schema rules reject malformed output at the boundary; an isolated execution environment is the only thing that can 
move a finding from "tested" to "confirmed"; a tamper-evident audit log records every step. No second model judges 
the first. The second witness is execution, in an environment that cannot reach the network.

Four structural commitments hold the design together. The AI does not decide verdicts. Code is only ever run inside 
an isolated sandbox. Nothing crosses a network boundary during analysis. The audit log is tamper-evident from end 
to end. Each commitment lives in a specific place in the code where it can be tested, which is what makes the 
architecture defensible rather than merely intended.

vulnforge is one worked example, not an implementation of this post. Other arrangements with different role 
boundaries would be consistent with similar conceptual frames. The point is that the model is one component in an 
arrangement, and the arrangement is what does the work. The attack surface of an AI vulnerability tool is not a 
property of the model; it is a property of the arrangement around the model.
