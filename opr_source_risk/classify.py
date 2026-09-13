from __future__ import annotations

from pathlib import Path

SKIP_DIR_NAMES = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "__pycache__",
    ".venv",
}
DOC_DIR_NAMES = {"docs", "doc", "examples", "example"}
TEST_DIR_NAMES = {"tests", "test", "testdata"}

CONFIG_NAMES = {
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "pkgbuild",
    "nginx.conf",
    "caddyfile",
}
CONFIG_SUFFIXES = {".service", ".socket", ".yml", ".yaml", ".toml", ".json", ".conf", ".pkla"}
SOURCE_SUFFIXES = {".go", ".py", ".rs", ".c", ".cc", ".cpp", ".h", ".js", ".ts", ".java", ".sh"}
DOC_SUFFIXES = {".md", ".rst", ".txt", ".adoc"}


def classify_path(rel: Path) -> str:
    parts = {p.lower() for p in rel.parts[:-1]}
    name = rel.name.lower()
    suffix = rel.suffix.lower()
    if parts & SKIP_DIR_NAMES:
        return "skip"
    if parts & DOC_DIR_NAMES or suffix in DOC_SUFFIXES:
        return "doc"
    if parts & TEST_DIR_NAMES or name.endswith("_test.go") or name.startswith("test_"):
        return "test"
    if name in CONFIG_NAMES or suffix in CONFIG_SUFFIXES or "sudoers" in name:
        return "config"
    if suffix in SOURCE_SUFFIXES:
        return "source"
    if "sudoers" in str(rel).lower() or name.endswith(".pkla"):
        return "config"
    return "other"


def inventory(root: Path) -> list[dict]:
    files: list[dict] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue
        if any(part in SKIP_DIR_NAMES for part in rel.parts):
            continue
        kind = classify_path(rel)
        if kind == "skip":
            continue
        files.append({"path": str(rel).replace("\\", "/"), "class": kind})
    return sorted(files, key=lambda f: f["path"])
