"""Scorers for evaluating patches against vulnerabilities.

These run inside Docker sandboxes to verify patches:
1. Apply the patch to the vulnerable source
2. Rebuild with sanitizers
3. Run the triggering input — does it still crash?
4. Run the test suite — any regressions?
"""

from parser_security_eval.models.scoring import PatchResult


async def apply_patch(sandbox_dir: str, patch_diff: str) -> bool:
    """Apply a unified diff to the source tree in the sandbox.

    Returns True if the patch applied cleanly.
    """
    raise NotImplementedError


async def rebuild_target(sandbox_dir: str, sanitizer: str = "address") -> bool:
    """Rebuild the parser target with the specified sanitizer.

    Returns True if compilation succeeded.
    """
    raise NotImplementedError


async def check_crash_eliminated(
    sandbox_dir: str,
    triggering_input_path: str,
    fuzz_target_binary: str,
) -> bool:
    """Run the triggering input against the patched binary.

    Returns True if the binary no longer crashes.
    """
    raise NotImplementedError


async def run_test_suite(sandbox_dir: str) -> bool:
    """Run the target's test suite in the sandbox.

    Returns True if all tests pass.
    """
    raise NotImplementedError


async def score_patch(
    sandbox_dir: str,
    patch_diff: str,
    triggering_input_path: str,
    fuzz_target_binary: str,
    sanitizer: str = "address",
) -> PatchResult:
    """Full scoring pipeline for a patch."""
    raise NotImplementedError
