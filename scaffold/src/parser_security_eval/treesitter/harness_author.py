"""The "write/refine the fuzz harness" step for the LLM-in-loop treatment arm.

Mirrors :class:`parser_security_eval.treesitter.fixer.LLMFixer`: a model-agnostic
pydantic-ai :class:`~pydantic_ai.Agent` that returns a validated structured result
(no text parsing), with the full prompt + solution logged to Logfire. Where the
fixer *patches* a crash, this author *writes the harness* the fuzzer runs — the
LLM's contribution to discovery, which the plain-libFuzzer control lacks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, cast

import logfire
from pydantic import BaseModel, Field
from pydantic_ai import Agent
from pydantic_ai.settings import ModelSettings

from parser_security_eval import prompts
from parser_security_eval.treesitter.models import GrammarTarget

# Same provider:model convention as the fixer. Defaults to Opus 5 — the treatment
# arm is the expensive, capability-sensitive half of the ablation.
DEFAULT_HARNESS_MODEL = "anthropic:claude-opus-5"


class HarnessOutput(BaseModel):
    """Structured harness-author result — enforced by pydantic-ai (no parsing)."""

    rationale: str = Field(
        description="One sentence: what scanner behavior this harness targets "
        "or what you changed since the last window."
    )
    harness_c: str = Field(
        description="The COMPLETE contents of harness.c — a full compilable file, "
        "not a diff or a snippet."
    )
    seeds_hex: list[str] = Field(
        default_factory=list,
        description="Hex-encoded seed inputs likely to exercise the scanner "
        "(may be empty).",
    )


@dataclass
class HarnessProposal:
    """A harness author's proposed harness.c plus seed inputs."""

    harness_c: str
    rationale: str
    seeds: list[bytes] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0


class HarnessAuthor(Protocol):
    """Proposes a libFuzzer harness (and seeds) for a grammar."""

    name: str

    def propose(
        self,
        target: GrammarTarget,
        symbol: str,
        scanner_source: str,
        reference_harness: str,
        *,
        previous_harness: str = "",
        feedback: str = "",
        has_scanner: bool = True,
    ) -> HarnessProposal: ...


def _decode_seeds(seeds_hex: list[str]) -> list[bytes]:
    """Best-effort hex→bytes; silently drop malformed entries."""
    out: list[bytes] = []
    for s in seeds_hex:
        try:
            out.append(bytes.fromhex(s.strip().replace(" ", "")))
        except ValueError:
            continue
    return out


class LLMHarnessAuthor:
    """Model-agnostic harness author via pydantic-ai.

    ``model`` is a ``provider:model`` string (e.g. ``anthropic:claude-opus-5``);
    the provider's API key is read from the environment. The harness comes back as
    a validated :class:`HarnessOutput`, so there is no text/regex parsing.
    """

    def __init__(
        self, model: str = DEFAULT_HARNESS_MODEL, max_tokens: int = 32768
    ) -> None:
        self.model = model
        self.name = model
        self.max_tokens = max_tokens

    def propose(
        self,
        target: GrammarTarget,
        symbol: str,
        scanner_source: str,
        reference_harness: str,
        *,
        previous_harness: str = "",
        feedback: str = "",
        has_scanner: bool = True,
    ) -> HarnessProposal:
        system = prompts.load("treesitter.harness_author_system")
        scanner_note = (
            "the full scanner is shown below"
            if has_scanner
            else "this grammar ships NO external scanner — target the generated "
            "parser and runtime edge cases instead"
        )
        user = prompts.load(
            "treesitter.harness_author_user",
            grammar=target.name,
            language=target.language,
            symbol=symbol,
            reference_harness=reference_harness,
            scanner_source=scanner_source[:8000] or "(no scanner source)",
            scanner_note=scanner_note,
            previous_harness=previous_harness,
            feedback=feedback,
        )
        agent = Agent(
            self.model,
            output_type=HarnessOutput,
            system_prompt=system,
            model_settings=ModelSettings(max_tokens=self.max_tokens),
        )
        with logfire.span(
            "harness author {grammar}",
            grammar=target.name,
            model=self.model,
            symbol=symbol,
        ):
            logfire.info(
                "harness prompt {grammar}",
                grammar=target.name,
                system_prompt=system,
                user_prompt=user,
                user_prompt_chars=len(user),
                scanner_chars=len(scanner_source),
            )
            result = agent.run_sync(user)
            out = cast("HarnessOutput", result.output)
            logfire.info(
                "harness solution {grammar}: {rationale}",
                grammar=target.name,
                rationale=out.rationale.strip(),
                solution=out.harness_c,
                solution_chars=len(out.harness_c),
                seed_count=len(out.seeds_hex),
                input_tokens=result.usage.input_tokens or 0,
                output_tokens=result.usage.output_tokens or 0,
            )
        return HarnessProposal(
            harness_c=out.harness_c.strip("\n") + "\n" if out.harness_c.strip() else "",
            rationale=out.rationale.strip(),
            seeds=_decode_seeds(out.seeds_hex),
            input_tokens=result.usage.input_tokens or 0,
            output_tokens=result.usage.output_tokens or 0,
        )
