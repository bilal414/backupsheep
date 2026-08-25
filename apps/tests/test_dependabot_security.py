from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]


class DependabotSecurityContractTests(TestCase):
    def test_every_shipped_dependency_surface_has_recurring_updates(self):
        configuration = (ROOT / ".github" / "dependabot.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("version: 2", configuration)
        for ecosystem in ("pip", "npm", "docker", "github-actions"):
            with self.subTest(ecosystem=ecosystem):
                self.assertIn(
                    f"package-ecosystem: {ecosystem}", configuration
                )
        self.assertEqual(configuration.count("interval: weekly"), 4)
        self.assertEqual(configuration.count("open-pull-requests-limit: 5"), 4)
