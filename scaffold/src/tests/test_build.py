"""Tests for oss-fuzz build script generation."""

import stat
from pathlib import Path


from parser_security_eval.sandbox.build import (
    find_missing_copy_targets,
    generate_build_sh,
    generate_dockerfile,
    validate_target_layout,
)


class TestGenerateDockerfile:
    def test_default_base_image(self) -> None:
        result = generate_dockerfile()
        assert result.startswith("FROM gcr.io/oss-fuzz-base/base-builder\n")

    def test_custom_base_image(self) -> None:
        result = generate_dockerfile(base_image="ubuntu:24.04")
        assert result.startswith("FROM ubuntu:24.04\n")

    def test_extra_packages(self) -> None:
        result = generate_dockerfile(extra_packages=["cmake", "libssl-dev"])
        assert "apt-get install -y cmake libssl-dev" in result

    def test_no_extra_packages(self) -> None:
        result = generate_dockerfile()
        assert "apt-get" not in result

    def test_git_project_source(self) -> None:
        url = "https://github.com/example/parser.git"
        result = generate_dockerfile(project_source=url)
        assert f"git clone --depth 1 {url} project" in result

    def test_local_project_source(self) -> None:
        result = generate_dockerfile(project_source="src/")
        assert "COPY src/ project/" in result

    def test_no_project_source(self) -> None:
        result = generate_dockerfile()
        assert "COPY build.sh $SRC/" in result
        assert "project" not in result

    def test_workdir_set(self) -> None:
        result = generate_dockerfile()
        assert "WORKDIR /src" in result

    def test_build_sh_copied(self) -> None:
        result = generate_dockerfile()
        assert "COPY build.sh $SRC/" in result

    def test_ends_with_newline(self) -> None:
        result = generate_dockerfile()
        assert result.endswith("\n")


class TestGenerateBuildSh:
    def test_shebang(self) -> None:
        result = generate_build_sh("test", [], [])
        assert result.startswith("#!/bin/bash -eu\n")

    def test_project_name_in_comment(self) -> None:
        result = generate_build_sh("myparser", [], [])
        assert "myparser" in result

    def test_cd_to_project(self) -> None:
        result = generate_build_sh("test", [], [])
        assert "cd $SRC/project" in result

    def test_build_commands_included(self) -> None:
        cmds = ["cmake -B build .", "make -C build -j$(nproc)"]
        result = generate_build_sh("test", cmds, [])
        for cmd in cmds:
            assert cmd in result

    def test_c_target_uses_cc(self) -> None:
        result = generate_build_sh("test", [], ["fuzz_parse.c"])
        assert "$CC $CFLAGS" in result
        assert "$LIB_FUZZING_ENGINE" in result
        assert "$OUT/fuzz_parse" in result

    def test_cpp_target_uses_cxx(self) -> None:
        result = generate_build_sh("test", [], ["fuzz_parse.cpp"])
        assert "$CXX $CXXFLAGS" in result
        assert "$LIB_FUZZING_ENGINE" in result
        assert "$OUT/fuzz_parse" in result

    def test_multiple_targets(self) -> None:
        targets = ["fuzz_a.c", "fuzz_b.cpp"]
        result = generate_build_sh("test", [], targets)
        assert "$OUT/fuzz_a" in result
        assert "$OUT/fuzz_b" in result

    def test_env_vars_referenced(self) -> None:
        result = generate_build_sh("test", [], ["fuzz.c"])
        for var in ("$CC", "$CFLAGS", "$LIB_FUZZING_ENGINE", "$OUT", "$SRC"):
            assert var in result


class TestValidateTargetLayout:
    def _create_valid_target(self, target_dir: Path) -> None:
        """Create a minimal valid target directory."""
        target_dir.mkdir(parents=True, exist_ok=True)

        dockerfile = target_dir / "Dockerfile"
        dockerfile.write_text("FROM gcr.io/oss-fuzz-base/base-builder\nWORKDIR /src\n")

        build_sh = target_dir / "build.sh"
        build_sh.write_text("#!/bin/bash -eu\necho hello\n")
        build_sh.chmod(build_sh.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)

        metadata = target_dir / "metadata.yaml"
        metadata.write_text('name: "test"\nlanguage: "c"\n')

    def test_valid_target(self, tmp_path: Path) -> None:
        self._create_valid_target(tmp_path)
        errors = validate_target_layout(tmp_path)
        assert errors == []

    def test_missing_dockerfile(self, tmp_path: Path) -> None:
        self._create_valid_target(tmp_path)
        (tmp_path / "Dockerfile").unlink()
        errors = validate_target_layout(tmp_path)
        assert any("Missing Dockerfile" in e for e in errors)

    def test_missing_build_sh(self, tmp_path: Path) -> None:
        self._create_valid_target(tmp_path)
        (tmp_path / "build.sh").unlink()
        errors = validate_target_layout(tmp_path)
        assert any("Missing build.sh" in e for e in errors)

    def test_missing_metadata(self, tmp_path: Path) -> None:
        self._create_valid_target(tmp_path)
        (tmp_path / "metadata.yaml").unlink()
        errors = validate_target_layout(tmp_path)
        assert any("Missing metadata.yaml" in e for e in errors)

    def test_dockerfile_missing_from(self, tmp_path: Path) -> None:
        self._create_valid_target(tmp_path)
        (tmp_path / "Dockerfile").write_text("RUN echo hello\n")
        errors = validate_target_layout(tmp_path)
        assert any("FROM" in e for e in errors)

    def test_build_sh_not_executable(self, tmp_path: Path) -> None:
        self._create_valid_target(tmp_path)
        build_sh = tmp_path / "build.sh"
        build_sh.chmod(stat.S_IRUSR | stat.S_IWUSR)  # remove exec bit
        errors = validate_target_layout(tmp_path)
        assert any("not executable" in e for e in errors)

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        self._create_valid_target(tmp_path)
        (tmp_path / "metadata.yaml").write_text("{{invalid: yaml: [}")
        errors = validate_target_layout(tmp_path)
        assert any("not valid YAML" in e for e in errors)

    def test_metadata_not_mapping(self, tmp_path: Path) -> None:
        self._create_valid_target(tmp_path)
        (tmp_path / "metadata.yaml").write_text("- just\n- a\n- list\n")
        errors = validate_target_layout(tmp_path)
        assert any("YAML mapping" in e for e in errors)

    def test_empty_directory(self, tmp_path: Path) -> None:
        errors = validate_target_layout(tmp_path)
        assert len(errors) == 3  # all three files missing

    def test_missing_copy_targets_detected(self, tmp_path: Path) -> None:
        self._create_valid_target(tmp_path)
        (tmp_path / "Dockerfile").write_text(
            "FROM gcr.io/oss-fuzz-base/base-builder\n"
            "COPY build.sh fuzzer.cc helper.h $SRC/\n"
        )
        errors = validate_target_layout(tmp_path)
        assert any("fuzzer.cc" in e for e in errors)
        assert any("helper.h" in e for e in errors)
        # build.sh exists, so it should NOT be flagged
        assert not any("build.sh" in e for e in errors)

    def test_no_false_positives_for_present_files(self, tmp_path: Path) -> None:
        self._create_valid_target(tmp_path)
        (tmp_path / "Dockerfile").write_text(
            "FROM gcr.io/oss-fuzz-base/base-builder\nCOPY build.sh $SRC/\n"
        )
        errors = validate_target_layout(tmp_path)
        assert errors == []


class TestFindMissingCopyTargets:
    def test_missing_files(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM base\nCOPY build.sh fuzzer.cc $SRC/\n")
        (tmp_path / "build.sh").write_text("#!/bin/bash\n")
        missing = find_missing_copy_targets(tmp_path, df)
        assert missing == ["fuzzer.cc"]

    def test_skips_env_vars(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM base\nCOPY $SRC/thing /dst/\n")
        missing = find_missing_copy_targets(tmp_path, df)
        assert missing == []

    def test_skips_absolute_paths(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM base\nCOPY /usr/local/bin/tool /dst/\n")
        missing = find_missing_copy_targets(tmp_path, df)
        assert missing == []

    def test_skips_urls(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM base\nADD https://example.com/file.tar.gz /dst/\n")
        missing = find_missing_copy_targets(tmp_path, df)
        assert missing == []

    def test_handles_copy_flags(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM base\nCOPY --from=builder /app/bin /dst/\n")
        missing = find_missing_copy_targets(tmp_path, df)
        assert missing == []

    def test_directories_counted(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM base\nCOPY seeds/ $SRC/seeds/\n")
        (tmp_path / "seeds").mkdir()
        missing = find_missing_copy_targets(tmp_path, df)
        assert missing == []

    def test_missing_directory(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM base\nCOPY pdf_seeds $SRC/\n")
        missing = find_missing_copy_targets(tmp_path, df)
        assert missing == ["pdf_seeds"]

    def test_multiple_copy_lines(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text(
            "FROM base\n"
            "COPY build.sh $SRC/\n"
            "COPY fuzzer.cc helper.h $SRC/\n"
            "ADD proto.proto $SRC/\n"
        )
        (tmp_path / "build.sh").write_text("#!/bin/bash\n")
        (tmp_path / "helper.h").write_text("#pragma once\n")
        missing = find_missing_copy_targets(tmp_path, df)
        assert sorted(missing) == ["fuzzer.cc", "proto.proto"]

    def test_comments_ignored(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM base\n# COPY commented_out.cc $SRC/\nCOPY build.sh $SRC/\n")
        (tmp_path / "build.sh").write_text("#!/bin/bash\n")
        missing = find_missing_copy_targets(tmp_path, df)
        assert missing == []
