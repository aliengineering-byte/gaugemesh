"""Original algebraic and refusal fixtures; no publisher examples."""
import copy
from decimal import Decimal, localcontext
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import mechanics
import oracle
import review
import beam_worker
import reporting


def request():
    return json.loads(Path(__file__).with_name("educational.json").read_text())


def quantity(value, unit):
    return {"value": str(value), "unit": unit}


class MechanicsTests(unittest.TestCase):
    def solve(self, value):
        data = mechanics.normalize(value)
        result = mechanics.solve(data)
        self.assertEqual(oracle.verify_calculation(data, result)["state"], "VERIFIED")
        return data, result

    def test_original_analytical_fixtures(self):
        # Independent derivation selects rational roots, not answers copied from the solver.
        cases = [
            ("0.001", [(1500, 600, 500)], 200, 320e6, [400]),
            ("0.001", [(1500, 600, 300)], 150, 247.5e6, [300]),
            ("0.001", [(1600, 600, 500), (400, 100, 500)], 200, 340e6, [400, -100]),
            ("0.003", [(10000, 600, 200), (1000, 50, 200)], 200, 1070e6, [200, -200]),
            ("0.001", [(1500, 600, 500), (400, 200, 500)], 200, 320e6, [400, 0]),
            ("0.001", [(1500, 600, 400)], 200, 320e6, [400]),
        ]
        for eps, layers, expected_c, expected_m, stresses in cases:
            with self.subTest(eps=eps, layers=layers):
                value = request()
                value["concrete"]["topCompressionStrain"]["value"] = eps
                value["reinforcement"] = [{"area": quantity(area, "mm2"), "depthFromCompressionFace": quantity(depth, "mm"),
                    "elasticModulus": quantity(200000, "MPa"), "yieldStress": quantity(fy, "MPa")} for area, depth, fy in layers]
                _, actual = self.solve(value)
                self.assertAlmostEqual(actual["neutralAxis_mm"], expected_c, delta=1e-8)
                self.assertAlmostEqual(actual["modelMoment_Nmm"], expected_m, delta=0.01)
                for layer, expected in zip(actual["steel"], stresses):
                    self.assertAlmostEqual(layer["stress_MPa"], expected, delta=1e-7)

    def test_permutation_and_geometric_similarity(self):
        value = request()
        value["reinforcement"].append({"area": quantity(400, "mm2"), "depthFromCompressionFace": quantity(100, "mm"),
            "elasticModulus": quantity(190000, "MPa"), "yieldStress": quantity(450, "MPa")})
        _, original = self.solve(value)
        value["reinforcement"].reverse()
        _, permuted = self.solve(value)
        self.assertAlmostEqual(original["modelMoment_Nmm"], permuted["modelMoment_Nmm"], delta=0.01)
        for dimension in value["geometry"].values():
            dimension["value"] = str(Decimal(dimension["value"]) * 2)
        for layer in value["reinforcement"]:
            layer["area"]["value"] = str(Decimal(layer["area"]["value"]) * 4)
            layer["depthFromCompressionFace"]["value"] = str(Decimal(layer["depthFromCompressionFace"]["value"]) * 2)
        _, scaled = self.solve(value)
        self.assertAlmostEqual(scaled["modelMoment_Nmm"], 8*original["modelMoment_Nmm"], delta=0.1)

    def test_independently_converted_us_case(self):
        value = request()
        value["profile"]["unitSystem"] = "US"
        # Independent dimensional definitions, deliberately not mechanics.UNITS.
        with localcontext() as ctx:
            ctx.prec = 45
            inch = Decimal("25.4")
            pound_force = Decimal("0.45359237") * Decimal("9.80665")
            def convert(q):
                original = Decimal(q["value"])
                units = {"mm": (inch, "in"), "mm2": (inch*inch, "in2"),
                    "MPa": (pound_force/(inch*inch), "psi"), "N": (pound_force, "lbf"),
                    "N*mm": (pound_force*inch, "lbf*in"), "kN*m": (pound_force*inch/Decimal(1000000), "lbf*in"), "1": (Decimal(1), "1")}
                factor, unit = units[q["unit"]]
                return quantity(original/factor, unit)
            def walk(item):
                if isinstance(item, dict):
                    if set(item) == {"value", "unit"}:
                        return convert(item)
                    return {key: walk(child) for key, child in item.items()}
                if isinstance(item, list):
                    return [walk(child) for child in item]
                return item
            value = walk(value)
        normalized, result = self.solve(value)
        self.assertAlmostEqual(result["neutralAxis_mm"], 200, delta=1e-8)
        self.assertAlmostEqual(result["modelMoment_Nmm"], 320e6, delta=0.01)
        self.assertAlmostEqual(normalized["demand_Nmm"], 250e6, delta=0.001)

    def test_rounding_never_changes_acceptance(self):
        data, result = self.solve(request())
        data["demand_Nmm"] = result["modelMoment_Nmm"] + 10
        self.assertEqual(oracle.compare_demand(data, result)["status"], "EXCEEDS_DECLARED_MODEL_RESPONSE")
        data["displayDecimals"] = 0
        self.assertEqual(oracle.compare_demand(data, result)["status"], "EXCEEDS_DECLARED_MODEL_RESPONSE")
        data["demand_Nmm"] = result["modelMoment_Nmm"] - 10
        self.assertEqual(oracle.compare_demand(data, result)["status"], "BELOW_DECLARED_MODEL_RESPONSE")
        data["demand_Nmm"] = result["modelMoment_Nmm"]
        self.assertEqual(oracle.compare_demand(data, result)["status"], "INDETERMINATE_NUMERICAL_TOLERANCE")

    def test_missing_conflicting_nonfinite_units_bounds_and_unsupported(self):
        changes = [lambda r: r["geometry"].pop("height"),
            lambda r: r["geometry"]["width"].update(unit="MPa"),
            lambda r: r["geometry"]["width"].update(unit=[]),
            lambda r: r["geometry"]["width"].update(value=True),
            lambda r: r["geometry"]["width"].update(value="NaN"),
            lambda r: r["geometry"]["width"].update(value="-1"),
            lambda r: r["scope"]["axialForce"].update(value="1e-999"),
            lambda r: r["scope"]["axialForce"].update(value="1e-999999999"),
            lambda r: r["reinforcement"][0]["depthFromCompressionFace"].update(value="800"),
            lambda r: r["scope"].update(prestressed=True),
            lambda r: r["scope"].update(section="T"),
            lambda r: r["scope"]["axialForce"].update(value="1"),
            lambda r: r["scope"]["torsion"].update(value="1"),
            lambda r: r["demand"].update(basis="GUESS"),
            lambda r: r["profile"].update(unitSystem="US"),
            lambda r: r["model"].update(approval="ASSUMED"),
            lambda r: r["model"].update(id="unusual-model")]
        for change in changes:
            value = request()
            change(value)
            with self.subTest(value=value), self.assertRaises(mechanics.ReviewStop):
                mechanics.normalize(value)
        with self.assertRaises(mechanics.ReviewStop):
            mechanics.strict_json('{"x":1,"x":2}')
        with self.assertRaises(mechanics.ReviewStop):
            mechanics.strict_json('{"x":NaN}')
        for text in ('[1e9999]', '[1e-9999]'):
            with self.assertRaises(mechanics.ReviewStop):
                mechanics.strict_json(text)

    def test_explicit_nonconvergence_retains_trace(self):
        value = request()
        value["solver"]["maxIterations"] = 1
        with self.assertRaises(mechanics.ReviewStop) as caught:
            mechanics.solve(mechanics.normalize(value))
        self.assertIn("NONCONVERGENCE", caught.exception.reason)
        self.assertEqual(len(caught.exception.details["trace"]), 1)

    def test_no_rights_switch_and_wrong_edition(self):
        value = request()
        value["mode"] = "AUTHORIZED_RULE_CHECKS"
        value["rules"]["standard"] = "ACI CODE-318-25"
        with self.assertRaises(mechanics.ReviewStop) as caught:
            review.admission(value, True)
        self.assertEqual(caught.exception.status, "SOURCE_AUTHORIZATION_REQUIRED")
        value["rules"]["standard"] = "ACI CODE-318-2099"
        with self.assertRaises(mechanics.ReviewStop) as caught:
            review.admission(value, True)
        self.assertIn("UNSUPPORTED_STANDARD_EDITION", caught.exception.reason)
        with self.assertRaises(mechanics.ReviewStop):
            review.admission(request(), False)

    def test_independent_oracle_detects_wrong_numerical_output(self):
        data, result = self.solve(request())
        changes = [lambda r: r.update(modelMoment_Nmm=r["modelMoment_Nmm"]+10000),
            lambda r: r.update(steel=[]), lambda r: r.update(concreteCentroid_mm=42),
            lambda r: r.update(concreteTopStress_MPa=42), lambda r: r.update(trace=[]),
            lambda r: r["trace"][0].update(residual_N=123)]
        for key, value in (("force_N", 0), ("strain_tension_positive", 2), ("sign", "wrong"), ("state", "wrong"), ("stress_MPa", float("nan"))):
            changes.append(lambda r, key=key, value=value: r["steel"][0].update({key: value}))
        for change in changes:
            changed = copy.deepcopy(result)
            change(changed)
            self.assertEqual(oracle.verify_calculation(data, changed)["state"], "FAILED")

    def test_complete_synthetic_result_independently_checked(self):
        value = request()
        data, calculation = self.solve(value)
        def rule_result(value, calculation):
            with patch.object(beam_worker, "read_stage", side_effect=lambda root, stage, *args:
                {"normalized": data} if stage == "input" else {"calculation": calculation}):
                return beam_worker.execute_stage(None, {"stage": "synthetic", "predecessor": "calculate.json",
                    "producerSha256": beam_worker.producer_digest(), "requestJson": json.dumps(value)}, {})["ruleResult"]
        result = rule_result(value, calculation)
        policy = value["rules"]["syntheticPolicy"]
        self.assertTrue(oracle.verify_outcome(data, calculation, policy, result)[0])
        for key in result:
            changed = copy.deepcopy(result)
            changed[key] = "FORGED"
            self.assertFalse(oracle.verify_outcome(data, calculation, policy, changed)[0], key)
        for key in result["comparison"]:
            changed = copy.deepcopy(result)
            changed["comparison"][key] = 1e99 if isinstance(changed["comparison"][key], (int, float)) else "FORGED"
            self.assertFalse(oracle.verify_outcome(data, calculation, policy, changed)[0], key)
        value["rules"]["syntheticPolicy"] = None
        no_policy = rule_result(value, calculation)
        self.assertTrue(oracle.verify_outcome(data, calculation, None, no_policy)[0])
        no_policy["comparison"] = result["comparison"]
        self.assertFalse(oracle.verify_outcome(data, calculation, None, no_policy)[0])

    def test_nonconvergence_claim_requires_independently_audited_trace(self):
        value = request()
        value["solver"]["maxIterations"] = 1
        data = mechanics.normalize(value)
        try:
            mechanics.solve(data)
            self.fail("fixture must not converge")
        except mechanics.ReviewStop as stop:
            calculation = {"status": stop.status, "field": stop.field, "reason": stop.reason, "details": stop.details}
        self.assertTrue(oracle.verify_refusal(data, calculation))
        self.assertFalse(oracle.verify_refusal(data, {"status": "HUMAN_REVIEW_REQUIRED", "reason": "NONCONVERGENCE"}))
        for change in (lambda c: c["details"].update(trace=[]),
            lambda c: c["details"]["trace"][0].update(residual_N=1e99),
            lambda c: c["details"]["trace"][0].update(depth_mm=2),
            lambda c: c.update(field="invented")):
            changed = copy.deepcopy(calculation)
            change(changed)
            self.assertFalse(oracle.verify_refusal(data, changed))
        # A one-iteration trace is not proof of a 128-iteration exhaustion.
        data["maxIterations"] = 128
        self.assertFalse(oracle.verify_refusal(data, calculation))

    def test_reports_stable_after_sorted_sidecar_reload(self):
        value = request()
        data, calculation = self.solve(value)
        result = review.report_base(value, "/fixture/gaugemesh", Path("/fixture/output"))
        result.update(executionState="verified", verificationState="VERIFIED", domainStatus="MECHANICS_ONLY",
            normalized=data, calculation=calculation, comparison=oracle.compare_demand(data, calculation))
        self.assertEqual(reporting.documents(result), reporting.documents(json.loads(json.dumps(result, sort_keys=True))))
        self.assertLess(len(reporting.documents(result)[1]), 10000)


if __name__ == "__main__":
    unittest.main()
