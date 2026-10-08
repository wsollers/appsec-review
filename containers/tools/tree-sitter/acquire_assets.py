"""One-time acquisition helper for the ignored, hash-locked Linux asset cache.

Run this only in the pinned Linux acquisition container documented in README.md.
Review runs and image builds never call it and never use the network.
"""

from pathlib import Path

from tree_sitter_language_pack import PackConfig, configure, prefetch


LANGUAGES = [
    "c", "cpp", "rust", "go", "java", "javascript", "typescript", "tsx",
    "csharp", "python", "php",
]


def main() -> None:
    destination = Path("/out/parsers-linux")
    destination.mkdir(parents=True, exist_ok=True)
    configure(PackConfig(cache_dir=str(destination)))
    prefetch(LANGUAGES)


if __name__ == "__main__":
    main()
