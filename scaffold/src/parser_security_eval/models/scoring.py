"""Data models for scoring and evaluation results."""

from pydantic import BaseModel


class PatchResult(BaseModel):
    """Result of applying and verifying a patch."""

    patch_applies: bool  # did the diff apply cleanly?
    compiles: bool  # did the patched code compile?
    crash_eliminated: bool  # does the triggering input no longer crash?
    tests_pass: bool  # do existing tests still pass?
    diff_lines: int  # size of the patch in lines changed
    regression_detected: bool = False

    @property
    def success(self) -> bool:
        return self.compiles and self.crash_eliminated and self.tests_pass


class ScoringResult(BaseModel):
    """Aggregate scoring for an eval run."""

    total_vulnerabilities: int
    patches_attempted: int
    patches_compiled: int
    crashes_eliminated: int
    tests_passed: int
    full_successes: int  # compiled + crash eliminated + tests pass

    @property
    def success_rate(self) -> float:
        if self.total_vulnerabilities == 0:
            return 0.0
        return self.full_successes / self.total_vulnerabilities
