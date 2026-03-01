# Tier 2 Parser Targets

## Added Targets

| Name | Format Type | OSS-Fuzz Project | Fuzz Target |
|------|-------------|-----------------|-------------|
| freetype | binary-font | freetype2 | freetype_fuzzer |
| libarchive | archive | libarchive | libarchive_fuzzer |
| expat | text-markup | expat | expat_fuzzer |
| pcre2 | regex | pcre2 | pcre2_fuzzer |

## Selection Criteria

All four targets were chosen because they satisfy:

1. **Active in OSS-Fuzz** — each has a maintained oss-fuzz project with established fuzzing
   infrastructure that the build scripts mirror.

2. **Rich historical bug record** — all four have long CVE histories and publicly documented
   memory-safety issues found by fuzz testing, giving the eval a meaningful baseline of known
   bug classes to rediscover.

3. **Diverse format types** — the set covers binary font rendering (freetype), multi-format
   archive unpacking (libarchive), XML/text-markup parsing (expat), and regular expression
   compilation/matching (pcre2). This is orthogonal to the Tier 1 set (image formats, XML,
   compression) and exercises different code paths and attack surfaces.

4. **Different bug classes than Tier 1** — freetype surfaces integer overflow and OOB reads in
   glyph rendering; libarchive surfaces path-traversal and decompression-bomb conditions;
   expat is historically susceptible to entity-expansion and billion-laughs style attacks;
   pcre2 surfaces backtracking super-linear complexity and JIT compiler bugs.

## File Layout

```
targets/
  freetype/
    Dockerfile
    build.sh
    metadata.yaml
  libarchive/
    Dockerfile
    build.sh
    metadata.yaml
  expat/
    Dockerfile
    build.sh
    metadata.yaml
  pcre2/
    Dockerfile
    build.sh
    metadata.yaml
```
