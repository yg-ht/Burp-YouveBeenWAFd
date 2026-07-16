"""Regression checks for source files imported by Burp's Jython runtime."""

import ast
from pathlib import Path
import unittest

from wafd.models import OriginAssessment, Rule


class JythonSyntaxCompatibilityTests(unittest.TestCase):
    """Reject Python 3-only syntax that Jython 2.7 cannot parse."""

    def test_runtime_sources_avoid_known_python_three_only_syntax(self):
        project_root = Path(__file__).resolve().parents[1]
        runtime_sources = [project_root / "BurpExtender.py"]
        runtime_sources.extend(sorted((project_root / "wafd").glob("*.py")))

        forbidden_nodes = tuple(
            node_type
            for node_name in (
                "AnnAssign",
                "AsyncFor",
                "AsyncFunctionDef",
                "AsyncWith",
                "Await",
                "FormattedValue",
                "JoinedStr",
                "NamedExpr",
                "Nonlocal",
                "YieldFrom",
            )
            for node_type in [getattr(ast, node_name, None)]
            if node_type is not None
        )

        failures = []
        for source_path in runtime_sources:
            tree = ast.parse(source_path.read_text(), filename=str(source_path))
            for node in ast.walk(tree):
                if isinstance(node, forbidden_nodes):
                    failures.append(
                        "%s:%s uses %s"
                        % (source_path.relative_to(project_root), node.lineno,
                           type(node).__name__)
                    )
                if isinstance(node, (ast.FunctionDef, ast.Lambda)):
                    arguments = node.args
                    if arguments.kwonlyargs or getattr(arguments, "posonlyargs", []):
                        failures.append(
                            "%s:%s uses keyword-only or positional-only arguments"
                            % (source_path.relative_to(project_root), node.lineno)
                        )
                    annotations = [argument.annotation for argument in arguments.args]
                    annotations.extend(
                        argument.annotation for argument in arguments.kwonlyargs
                    )
                    if any(annotation is not None for annotation in annotations):
                        failures.append(
                            "%s:%s uses parameter annotations"
                            % (source_path.relative_to(project_root), node.lineno)
                        )
                    if getattr(node, "returns", None) is not None:
                        failures.append(
                            "%s:%s uses a return annotation"
                            % (source_path.relative_to(project_root), node.lineno)
                        )

        self.assertEqual([], failures, "\n".join(failures))


class PlainModelCompatibilityTests(unittest.TestCase):
    """Ensure Python 2-compatible constructors retain safe default behaviour."""

    def test_rule_matcher_defaults_are_not_shared(self):
        first = Rule("first", "First", "group", 1)
        second = Rule("second", "Second", "group", 1)

        first.matcher["status"] = 403

        self.assertEqual({}, second.matcher)

    def test_assessment_evidence_defaults_are_not_shared(self):
        first = OriginAssessment("https://first.example")
        second = OriginAssessment("https://second.example")

        first.evidence.append("marker")

        self.assertEqual([], second.evidence)

    def test_assessment_history_defaults_are_not_shared(self):
        first = OriginAssessment("https://first.example")
        second = OriginAssessment("https://second.example")

        first.quality_states[("rule", "probe")] = "state"
        first.determinations.append("determination")

        self.assertEqual({}, second.quality_states)
        self.assertEqual([], second.determinations)


if __name__ == "__main__":
    unittest.main()
