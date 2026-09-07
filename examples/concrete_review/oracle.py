"""Independent 60-digit active-state algebra; does not import the primary solver.

Each steel state gives K*c^2 + (E-Y)*c - D = 0. No bisection, shared
stress helper, standards text, empirical code factors, or lookup tables.
"""
from decimal import Decimal, localcontext
from itertools import product
import math


def solve_active_states(data):
    with localcontext() as context:
        context.prec = 60
        dec = lambda value: Decimal(str(value))
        h, eps = dec(data["h_mm"]), dec(data["eps_top"])
        k = dec(data["b_mm"]) * dec(data["Ec_MPa"]) * eps / 2
        layers = [{key: dec(value) for key, value in layer.items()} for layer in data["layers"]]
        candidates = []
        for states in product((-1, 0, 1), repeat=len(layers)):
            yielded = sum((state * layer["area_mm2"] * layer["fy_MPa"] for state, layer in zip(states, layers) if state), Decimal(0))
            elastic = sum((layer["area_mm2"] * layer["Es_MPa"] * eps for state, layer in zip(states, layers) if not state), Decimal(0))
            depth_sum = sum((layer["area_mm2"] * layer["Es_MPa"] * eps * layer["depth_mm"] for state, layer in zip(states, layers) if not state), Decimal(0))
            b = elastic - yielded
            if depth_sum == 0:
                if yielded <= 0:
                    continue
                c = yielded / k
            else:
                discriminant = (b*b + 4*k*depth_sum).sqrt()
                c = 2*depth_sum / (b + discriminant) if b >= 0 else (discriminant - b) / (2*k)
            if not 0 < c < h:
                continue
            forces, stresses = [], []
            valid = True
            for state, layer in zip(states, layers):
                trial = layer["Es_MPa"] * eps * (layer["depth_mm"] / c - 1)
                fy = layer["fy_MPa"]
                boundary = Decimal("1e-45") * max(Decimal(1), fy, abs(trial))
                if (state == 0 and abs(trial) > fy + boundary) or (state == 1 and trial < fy - boundary) or (state == -1 and trial > -fy + boundary):
                    valid = False
                    break
                stress = trial if state == 0 else state * fy
                stresses.append(stress)
                forces.append(layer["area_mm2"] * stress)
            if not valid:
                continue
            compression = k*c
            moment = sum((force * layer["depth_mm"] for force, layer in zip(forces, layers)), Decimal(0)) - k*c*c/3
            identity = sum((force * (layer["depth_mm"]-c) for force, layer in zip(forces, layers)), Decimal(0)) + 2*k*c*c/3
            candidate = {"neutralAxis_mm": c, "modelMoment_Nmm": moment, "identityMoment_Nmm": identity,
                "concreteCompression_N": compression, "residual_N": compression-sum(forces), "steelStress_MPa": stresses,
                "states": list(states), "polynomial": {"K": k, "EminusY": b, "D": depth_sum}}
            if not any(abs(c - old["neutralAxis_mm"]) < Decimal("1e-40") * h for old in candidates):
                candidates.append(candidate)
        if len(candidates) != 1:
            raise ValueError("Independent oracle did not find exactly one admissible root")
        def serial(value):
            if isinstance(value, Decimal):
                return str(value)
            if isinstance(value, dict):
                return {key: serial(item) for key, item in value.items()}
            if isinstance(value, list):
                return [serial(item) for item in value]
            return value
        return {"method": "independent_decimal_active_set", "precisionDigits": 60, **serial(candidates[0])}


def verify_calculation(data, calculation):
    oracle = solve_active_states(data)
    relative = data["independentRelativeTolerance"]
    checks = []
    def finite(value):
        return type(value) in (int, float) and math.isfinite(value)
    def check_number(field, actual, expected, absolute=0):
        expected = float(expected)
        tolerance = absolute + relative * max(1, abs(expected))
        checks.append({"field": field, "primary": actual, "independentDecimal": str(expected),
            "tolerance": tolerance, "passed": finite(actual) and abs(actual-expected) <= tolerance})
    for key, absolute in (("neutralAxis_mm", data["depthTolerance_mm"]),
                          ("concreteCompression_N", data["forceTolerance_N"]),
                          ("modelMoment_Nmm", data["forceTolerance_N"] * data["h_mm"] * 4)):
        check_number(key, calculation.get(key), oracle[key], absolute)
    residual = calculation.get("residual_N")
    checks.append({"field": "force_equilibrium", "passed": finite(residual) and abs(residual) <= data["forceTolerance_N"]})
    with localcontext() as context:
        context.prec = 60
        checks.append({"field": "independent_moment_identity", "passed":
            abs(Decimal(oracle["modelMoment_Nmm"]) - Decimal(oracle["identityMoment_Nmm"])) <= Decimal("1e-40") * max(Decimal(1), abs(Decimal(oracle["modelMoment_Nmm"])))})
        dec = lambda value: Decimal(str(value))
        c = calculation.get("neutralAxis_mm")
        actual_layers = calculation.get("steel")
        shape_ok = isinstance(actual_layers, list) and len(actual_layers) == len(data["layers"]) and all(isinstance(layer, dict) for layer in actual_layers)
        checks.append({"field": "steel_layer_count_and_shape", "passed": shape_ok})
        if finite(c) and 0 < c < data["h_mm"]:
            c, eps = dec(c), dec(data["eps_top"])
            compression = dec(data["b_mm"]) * dec(data["Ec_MPa"]) * eps * c / 2
            check_number("concreteCentroid_mm", calculation.get("concreteCentroid_mm"), c/3, data["depthTolerance_mm"])
            check_number("concreteTopStress_MPa", calculation.get("concreteTopStress_MPa"), dec(data["Ec_MPa"])*eps)
            forces = []
            for index, layer in enumerate(data["layers"]):
                strain = eps * (dec(layer["depth_mm"])/c - 1)
                trial, fy = dec(layer["Es_MPa"])*strain, dec(layer["fy_MPa"])
                stress = min(fy, max(-fy, trial))
                force = dec(layer["area_mm2"])*stress
                forces.append(force)
                if shape_ok:
                    actual = actual_layers[index]
                    for key, expected in (("strain_tension_positive", strain), ("stress_MPa", stress), ("force_N", force)):
                        check_number(f"steel[{index}].{key}", actual.get(key), expected, 1e-8)
                    sign = "near_zero" if abs(stress) <= Decimal("1e-8") else "tension" if strain > 0 else "compression"
                    state = "yield_boundary" if abs(abs(trial)-fy) <= Decimal("1e-8") else "yielded" if abs(trial) > fy else "elastic"
                    checks.append({"field": f"steel[{index}].sign_and_state", "passed": actual.get("sign") == sign and actual.get("state") == state})
            check_number("reported_residual_identity", residual, compression-sum(forces), data["forceTolerance_N"] * 0.001)
        else:
            checks.append({"field": "admissible_reported_depth", "passed": False})
        trace = calculation.get("trace")
        trace_ok = isinstance(trace, list) and 1 <= len(trace) <= data["maxIterations"] and calculation.get("iterations") == len(trace)
        lower, upper = 0.0, data["h_mm"]
        if trace_ok:
            for index, item in enumerate(trace):
                if not isinstance(item, dict) or item.get("iteration") != index+1 or any(not finite(item.get(key)) for key in ("lower_mm", "upper_mm", "depth_mm", "residual_N")):
                    trace_ok = False
                    break
                depth = (lower+upper)/2
                if item["lower_mm"] != lower or item["upper_mm"] != upper or item["depth_mm"] != depth or depth <= 0:
                    trace_ok = False
                    break
                point = dec(depth)
                force = dec(data["b_mm"])*dec(data["Ec_MPa"])*dec(data["eps_top"])*point/2
                for layer in data["layers"]:
                    trial = dec(layer["Es_MPa"])*dec(data["eps_top"])*(dec(layer["depth_mm"])/point-1)
                    force -= dec(layer["area_mm2"])*min(dec(layer["fy_MPa"]), max(-dec(layer["fy_MPa"]), trial))
                if abs(item["residual_N"]-float(force)) > 1e-7 + relative*max(1,abs(float(force))):
                    trace_ok = False
                    break
                if item["residual_N"] > 0: upper = depth
                else: lower = depth
            trace_ok = trace_ok and trace[-1]["depth_mm"] == calculation.get("neutralAxis_mm") and trace[-1]["residual_N"] == residual and trace[-1]["upper_mm"]-trace[-1]["lower_mm"] <= data["depthTolerance_mm"]
        checks.append({"field": "bounded_convergence_trace", "passed": bool(trace_ok)})
        checks.append({"field": "declared_method_and_model", "passed": calculation.get("method") == "bounded_bisection" and calculation.get("model") == data["model"] and calculation.get("status") == "MECHANICS_ONLY"})
    return {"state": "VERIFIED" if all(check["passed"] for check in checks) else "FAILED",
        "method": oracle["method"], "checks": checks, "oracle": oracle}


def compare_demand(data, calculation, ratio_limit=1.0):
    """Unrounded comparison of prescribed-strain response; not a code capacity."""
    model = calculation["modelMoment_Nmm"]
    bound = 4 * data["forceTolerance_N"] * data["h_mm"] + data["independentRelativeTolerance"] * abs(model)
    difference = ratio_limit * model - data["demand_Nmm"]
    status = "INDETERMINATE_NUMERICAL_TOLERANCE" if abs(difference) <= bound else (
        "BELOW_DECLARED_MODEL_RESPONSE" if difference > 0 else "EXCEEDS_DECLARED_MODEL_RESPONSE")
    return {"status": status, "demand_Nmm": data["demand_Nmm"], "modelResponse_Nmm": model,
        "ratio": data["demand_Nmm"] / model, "threshold": ratio_limit, "comparisonBound_Nmm": bound,
        "acceptanceRounding": "NONE", "designCapacity": "NOT_EVALUATED", "reductionFactor": "NOT_APPLIED"}


def verify_refusal(data, calculation):
    """Audit the declared bounded stop, independently of the primary solver."""
    reason = "NONCONVERGENCE: both force and depth tolerances not reached within maxIterations or floating-point progress ceased"
    if set(calculation) != {"status", "field", "reason", "details"} or calculation.get("status") != "HUMAN_REVIEW_REQUIRED" or calculation.get("field") != "solver" or calculation.get("reason") != reason:
        return False
    details = calculation.get("details")
    if not isinstance(details, dict) or set(details) != {"trace"}:
        return False
    trace = details["trace"]
    if not isinstance(trace, list) or not 1 <= len(trace) <= data["maxIterations"]:
        return False
    with localcontext() as context:
        context.prec = 60
        dec = lambda value: Decimal(str(value))
        lower, upper = 0.0, data["h_mm"]
        stagnant = False
        for index, item in enumerate(trace):
            if not isinstance(item, dict) or set(item) != {"iteration", "lower_mm", "upper_mm", "depth_mm", "residual_N"} or item["iteration"] != index+1 or any(type(item[key]) not in (float, int) or not math.isfinite(item[key]) for key in ("lower_mm", "upper_mm", "depth_mm", "residual_N")):
                return False
            depth = (lower+upper)/2
            if item["lower_mm"] != lower or item["upper_mm"] != upper or item["depth_mm"] != depth or depth <= 0:
                return False
            point = dec(depth)
            force = dec(data["b_mm"])*dec(data["Ec_MPa"])*dec(data["eps_top"])*point/2
            for layer in data["layers"]:
                trial = dec(layer["Es_MPa"])*dec(data["eps_top"])*(dec(layer["depth_mm"])/point-1)
                force -= dec(layer["area_mm2"])*min(dec(layer["fy_MPa"]), max(-dec(layer["fy_MPa"]), trial))
            if abs(item["residual_N"]-float(force)) > 1e-7 + data["independentRelativeTolerance"]*max(1,abs(float(force))):
                return False
            if abs(item["residual_N"]) <= data["forceTolerance_N"] and upper-lower <= data["depthTolerance_mm"]:
                return False
            stagnant = depth == (upper if item["residual_N"] > 0 else lower)
            if stagnant and index != len(trace)-1:
                return False
            if item["residual_N"] > 0: upper = depth
            else: lower = depth
        return stagnant or len(trace) == data["maxIterations"]


def verify_rule_result(data, calculation, policy, result):
    """Independent Decimal reconstruction of every synthetic field; no saved bound is trusted."""
    checked = calculation.get("status") == "MECHANICS_ONLY" and policy is not None
    expected = {"label": "SYNTHETIC", "ruleSet": policy, "standardRules": "SOURCE_AUTHORIZATION_REQUIRED",
        "implementedStandardRules": [], "status": "CHECKED_SYNTHETIC_ONLY" if checked else "NOT_EVALUATED",
        "locator": "original:SYNTHETIC_MODEL_DEMAND_MARGIN/1", "implementationVersion": "0.1.0",
        "applicability": "declared original model response and caller-supplied dimensionless threshold",
        "units": "dimensionless ratio; moments normalized to N*mm", "comparison": None}
    if not isinstance(result, dict) or set(result) != set(expected) or any(result[key] != value for key, value in expected.items() if key != "comparison"):
        return False
    if not checked:
        return result["comparison"] is None
    with localcontext() as context:
        context.prec = 60
        dec = lambda value: Decimal(str(value))
        model, demand, ratio = dec(calculation["modelMoment_Nmm"]), dec(data["demand_Nmm"]), Decimal(policy["maximumRatio"])
        bound = 4*dec(data["forceTolerance_N"])*dec(data["h_mm"]) + dec(data["independentRelativeTolerance"])*abs(model)
        delta = ratio*model-demand
        status = "INDETERMINATE_NUMERICAL_TOLERANCE" if abs(delta) <= bound else "BELOW_DECLARED_MODEL_RESPONSE" if delta > 0 else "EXCEEDS_DECLARED_MODEL_RESPONSE"
        comparison = {"status": status, "demand_Nmm": demand, "modelResponse_Nmm": model,
            "ratio": demand/model, "threshold": ratio, "comparisonBound_Nmm": bound,
            "acceptanceRounding": "NONE", "designCapacity": "NOT_EVALUATED", "reductionFactor": "NOT_APPLIED"}
        actual = result["comparison"]
        if not isinstance(actual, dict) or set(actual) != set(comparison):
            return False
        for key, value in comparison.items():
            if isinstance(value, Decimal):
                if type(actual[key]) not in (float, int) or not math.isfinite(actual[key]) or abs(dec(actual[key])-value) > Decimal("1e-14")*max(Decimal(1), abs(value)):
                    return False
            elif actual[key] != value:
                return False
        return True


def verify_outcome(data, calculation, policy, rule_result):
    if calculation.get("status") == "MECHANICS_ONLY":
        verification = verify_calculation(data, calculation)
        consistent = verification["state"] == "VERIFIED"
    else:
        consistent = verify_refusal(data, calculation)
        verification = {"state": "NOT_EVALUATED", "reason": "No converged calculation to verify",
            "checks": [{"field": "declared_nonconvergence", "passed": consistent}]}
    policy_passed = verify_rule_result(data, calculation, policy, rule_result)
    verification["checks"].append({"field": "original_synthetic_policy", "passed": policy_passed})
    consistent = consistent and policy_passed
    if not consistent:
        verification["state"] = "FAILED"
    return consistent, verification
