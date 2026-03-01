"""Prompt loading utilities for parser-security-eval.

Usage::

    from parser_security_eval import prompts

    system_prompt = prompts.load("patching.system")
    user_prompt = prompts.load(
        "harness.user",
        target_name="libpng",
        format_type="image",
        language="c",
        build_sh="...",
        existing_harnesses_section="...",
    )
"""

from parser_security_eval.prompts.loader import load, render

__all__ = ["load", "render"]
