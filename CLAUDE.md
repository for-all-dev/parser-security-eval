# Parser Security Eval

Parsers are bad-- it'd be great if they were less bad. One way to do this would be to make frontier AI really good at writing secure parsers, refactoring insecure parsers into secure parsers. Ideally, there'd be a parser security RL environment, but an eval is a good place to start. 

## agent architecture

1. given a parser-- readable source, but executable
   - it'd be nice to drop-in / plug'n'play different parser codebases.
   - rely on oss-fuzz liberally https://github.com/google/oss-fuzz in architecture and implementation
2. a generator tries to find an input that will crash it
   1. a redteam agent/swarm can update the libafl code, or even like each agent can greenfield its own libafl crate?
3. blueteam agent patches what it just found

### cruxes
- what is the incidence of vulns per unit walltime of fuzzing in targeted parsers?

## project structure/style

- use monorepo features for any mixed build needs.
- use docker orchestration, maybe with compose.yml? if you like.
- `pydantic.BaseModels`
- `uv run ruff check --fix` and `uv run ruff format` and `uv run pytest` and `uv run ty check`
   - note: use typehints, but not pyright or numpy. `ty` is a new typechecker by astral. 
