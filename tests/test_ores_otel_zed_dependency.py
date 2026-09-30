from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OresOtelZedDependencyTest(unittest.TestCase):
    def test_next_loggers_is_a_zed_dependency(self) -> None:
        manifest = tomllib.loads((ROOT / ".zpkg.toml").read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["dependencies"]["oresoftware/next-loggers"],
            "^0.1.0",
        )


if __name__ == "__main__":
    unittest.main()
