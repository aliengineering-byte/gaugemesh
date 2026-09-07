"""Original educational section equilibrium; no standards-derived rules or factors."""
from decimal import Decimal, InvalidOperation
import json
import math

VERSION = "0.1.0"
MODEL = "original-linear-compression-bilinear-steel/1"
ASSUMPTIONS = ["plane_sections", "concrete_tension_ignored", "linear_concrete_compression",
    "elastic_perfectly_plastic_steel", "steel_displacement_ignored", "prescribed_top_strain_not_code_limit"]
EXCLUSIONS = ["shear", "development_anchorage", "cover_spacing", "deflection", "durability", "fire",
    "stability", "seismic_detailing", "construction_quality", "system_behavior"]
# Dimensional definitions, not empirical design coefficients. Decimal quotients
# (psi/ksi) and normalization use 28 significant digits before float computation.
UNITS = {"mm": ("length", Decimal(1), "SI"), "m": ("length", Decimal(1000), "SI"),
    "in": ("length", Decimal("25.4"), "US"), "ft": ("length", Decimal("304.8"), "US"),
    "mm2": ("area", Decimal(1), "SI"), "in2": ("area", Decimal("645.16"), "US"),
    "MPa": ("stress", Decimal(1), "SI"), "GPa": ("stress", Decimal(1000), "SI"),
    "psi": ("stress", Decimal("4.4482216152605") / Decimal("645.16"), "US"),
    "ksi": ("stress", Decimal("4448.2216152605") / Decimal("645.16"), "US"),
    "N": ("force", Decimal(1), "SI"), "kN": ("force", Decimal(1000), "SI"),
    "lbf": ("force", Decimal("4.4482216152605"), "US"), "kip": ("force", Decimal("4448.2216152605"), "US"),
    "N*mm": ("moment", Decimal(1), "SI"), "kN*m": ("moment", Decimal(1000000), "SI"),
    "lbf*in": ("moment", Decimal("112.9848290276167"), "US"),
    "kip*ft": ("moment", Decimal("1355817.9483314004"), "US"),
    "1": ("strain", Decimal(1), "ANY")}


class ReviewStop(ValueError):
    def __init__(self, status, field, reason, details=None):
        self.status, self.field, self.reason = status, field, reason
        self.details = details
        super().__init__(f"{status}: {field}: {reason}")


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ReviewStop("NEEDS_INPUT", key, "conflicting duplicate JSON key")
            result[key] = value
        return result
    def invalid(value):
        raise ReviewStop("NEEDS_INPUT", "number", "nonfinite JSON number: " + value)
    def finite_float(value):
        result = float(value)
        if not math.isfinite(result) or (result == 0 and not Decimal(value).is_zero()):
            raise ReviewStop("NEEDS_INPUT", "number", "JSON number outside representable range")
        return result
    return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid, parse_float=finite_float)


def fields(value, names, path):
    if not isinstance(value, dict):
        raise ReviewStop("NEEDS_INPUT", path, "explicit object required")
    missing, extra = set(names) - value.keys(), value.keys() - set(names)
    if missing or extra:
        raise ReviewStop("NEEDS_INPUT", path, f"missing={sorted(missing)} unsupported={sorted(extra)}")


def decimal(value, field):
    if not isinstance(value, str) or len(value) > 64:
        raise ReviewStop("NEEDS_INPUT", field, "explicit finite decimal string required")
    try:
        number = Decimal(value)
    except InvalidOperation as error:
        raise ReviewStop("NEEDS_INPUT", field, "invalid decimal") from error
    if not number.is_finite() or number.copy_abs() > Decimal("1e15") or (not number.is_zero() and number.adjusted() < -300):
        raise ReviewStop("NEEDS_INPUT", field, "nonfinite or outside computational range")
    return number


def normalize(request):
    fields(request, ["schemaVersion", "mode", "profile", "scope", "geometry", "reinforcement", "concrete",
        "model", "demand", "solver", "rules"], "request")
    if request["schemaVersion"] != "gaugemesh.concrete-review-request/1":
        raise ReviewStop("NEEDS_INPUT", "schemaVersion", "unsupported request version")
    if request["mode"] not in ("MECHANICS_ONLY", "AUTHORIZED_RULE_CHECKS"):
        raise ReviewStop("NEEDS_INPUT", "mode", "select an explicit supported mode")
    profile = request["profile"]
    fields(profile, ["purpose", "jurisdiction", "governingCode", "amendments", "referencedStandards",
        "errataSnapshot", "unitSystem", "designScope", "confirmationSource"], "profile")
    if profile["unitSystem"] not in ("SI", "US"):
        raise ReviewStop("NEEDS_INPUT", "profile.unitSystem", "SI or US must be declared")
    if not isinstance(profile["confirmationSource"], str) or not profile["confirmationSource"].strip():
        raise ReviewStop("NEEDS_INPUT", "profile.confirmationSource", "explicit confirmation source required")
    if profile["purpose"] != "EDUCATIONAL_NO_JURISDICTION" or profile["jurisdiction"] is not None:
        raise ReviewStop("OUT_OF_SCOPE", "profile", "this consumer supports educational/no-jurisdiction use only")
    if profile["designScope"] != "RECTANGULAR_BEAM_UNIAXIAL_FLEXURE":
        raise ReviewStop("OUT_OF_SCOPE", "profile.designScope", "only the declared beam section scope is implemented")
    if profile["governingCode"] is not None or profile["amendments"] != [] or profile["referencedStandards"] != []:
        raise ReviewStop("SOURCE_AUTHORIZATION_REQUIRED", "profile", "no adopted-code/edition assessment is implemented")
    if profile["errataSnapshot"] != "NOT_APPLICABLE_NO_NORMATIVE_RULES":
        raise ReviewStop("SOURCE_AUTHORIZATION_REQUIRED", "profile.errataSnapshot", "no normative errata content is loaded")
    trace = []
    def quantity(value, dimension, path, low, high, positive=False):
        fields(value, ["value", "unit"], path)
        unit = value["unit"]
        if not isinstance(unit, str) or unit not in UNITS or UNITS[unit][0] != dimension:
            raise ReviewStop("NEEDS_INPUT", path, "unit has the wrong dimension or is unsupported")
        _, factor, system = UNITS[unit]
        if system not in (profile["unitSystem"], "ANY"):
            raise ReviewStop("NEEDS_INPUT", path, "unit conflicts with declared unit system")
        number = decimal(value["value"], path) * factor
        if not Decimal(str(low)) <= number <= Decimal(str(high)) or (positive and number == 0):
            raise ReviewStop("NEEDS_INPUT", path, "outside explicitly supported computational bounds")
        if number != 0 and float(number) == 0:
            raise ReviewStop("NEEDS_INPUT", path, "nonzero value is below representable computational range")
        trace.append({"field": path, "original": value, "factor": str(factor), "normalizedDecimal": str(number),
            "normalizedUnit": {"length": "mm", "area": "mm2", "stress": "MPa", "force": "N", "moment": "N*mm", "strain": "1"}[dimension]})
        return float(number)
    scope = request["scope"]
    fields(scope, ["member", "section", "prestressed", "axialForce", "torsion", "compressionFace"], "scope")
    if scope["member"] != "beam" or scope["section"] != "rectangular" or scope["prestressed"] is not False:
        raise ReviewStop("OUT_OF_SCOPE", "scope", "nonprestressed rectangular beam required")
    if scope["compressionFace"] not in ("top", "bottom"):
        raise ReviewStop("NEEDS_INPUT", "scope.compressionFace", "declare the compression face and measure all depths from it")
    if quantity(scope["axialForce"], "force", "scope.axialForce", -1e12, 1e12) != 0 or quantity(scope["torsion"], "moment", "scope.torsion", -1e15, 1e15) != 0:
        raise ReviewStop("OUT_OF_SCOPE", "scope", "nonzero axial force or torsion is not supported")
    geometry, material = request["geometry"], request["concrete"]
    fields(geometry, ["width", "height"], "geometry")
    b = quantity(geometry["width"], "length", "geometry.width", 1, 1e5)
    h = quantity(geometry["height"], "length", "geometry.height", 1, 1e5)
    fields(material, ["elasticModulus", "topCompressionStrain"], "concrete")
    ec = quantity(material["elasticModulus"], "stress", "concrete.elasticModulus", 1, 1e6)
    eps = quantity(material["topCompressionStrain"], "strain", "concrete.topCompressionStrain", 1e-8, 0.1)
    model = request["model"]
    fields(model, ["id", "acceptedAssumptions", "approval"], "model")
    if model["id"] != MODEL or model["acceptedAssumptions"] != ASSUMPTIONS:
        raise ReviewStop("OUT_OF_SCOPE", "model", "only this exact declared original constitutive model is supported")
    if model["approval"] != "EXPLICIT_REQUEST":
        raise ReviewStop("NEEDS_INPUT", "model.approval", "explicit assumption approval required")
    layers = request["reinforcement"]
    if not isinstance(layers, list) or not 1 <= len(layers) <= 2:
        raise ReviewStop("OUT_OF_SCOPE", "reinforcement", "one or two explicitly located layers supported")
    normalized_layers = []
    for index, layer in enumerate(layers):
        prefix = f"reinforcement[{index}]"
        fields(layer, ["area", "depthFromCompressionFace", "elasticModulus", "yieldStress"], prefix)
        area = quantity(layer["area"], "area", prefix + ".area", 1e-6, b*h)
        depth = quantity(layer["depthFromCompressionFace"], "length", prefix + ".depth", 1e-6, h)
        if depth >= h:
            raise ReviewStop("NEEDS_INPUT", prefix, "reinforcement depth must lie strictly inside the section")
        es = quantity(layer["elasticModulus"], "stress", prefix + ".elasticModulus", 1, 1e7)
        fy = quantity(layer["yieldStress"], "stress", prefix + ".yieldStress", 1e-6, 1e5)
        normalized_layers.append({"area_mm2": area, "depth_mm": depth, "Es_MPa": es, "fy_MPa": fy})
    if sum(layer["area_mm2"] for layer in normalized_layers) >= b*h:
        raise ReviewStop("NEEDS_INPUT", "reinforcement", "reinforcement area cannot fill/exceed the gross section")
    demand = request["demand"]
    fields(demand, ["moment", "basis"], "demand")
    if demand["basis"] not in ("SERVICE", "FACTORED"):
        raise ReviewStop("NEEDS_INPUT", "demand.basis", "SERVICE or FACTORED must be explicit; no factors are applied")
    moment = quantity(demand["moment"], "moment", "demand.moment", 0, 1e15)
    solver = request["solver"]
    fields(solver, ["forceTolerance", "depthTolerance", "maxIterations", "independentRelativeTolerance", "displayDecimals"], "solver")
    force_tol = quantity(solver["forceTolerance"], "force", "solver.forceTolerance", 1e-9, 0.01)
    depth_tol = quantity(solver["depthTolerance"], "length", "solver.depthTolerance", 1e-12, 1e-5)
    relative_tol = float(decimal(solver["independentRelativeTolerance"], "solver.independentRelativeTolerance"))
    if not 1e-12 <= relative_tol <= 1e-7 or type(solver["maxIterations"]) is not int or not 1 <= solver["maxIterations"] <= 128:
        raise ReviewStop("NEEDS_INPUT", "solver", "unsupported tolerance or iteration bound")
    if type(solver["displayDecimals"]) is not int or not 0 <= solver["displayDecimals"] <= 8:
        raise ReviewStop("NEEDS_INPUT", "solver.displayDecimals", "integer 0 through 8 required")
    fields(request["rules"], ["standard", "syntheticPolicy"], "rules")
    if request["mode"] == "AUTHORIZED_RULE_CHECKS" or request["rules"]["standard"] is not None:
        raise ReviewStop("SOURCE_AUTHORIZATION_REQUIRED", "rules.standard", "no authorized standards rule/checker is installed; edition selection does not grant rights")
    synthetic = request["rules"]["syntheticPolicy"]
    if synthetic is not None:
        fields(synthetic, ["id", "maximumRatio"], "rules.syntheticPolicy")
        if synthetic["id"] != "SYNTHETIC_MODEL_DEMAND_MARGIN/1" or not Decimal("0.01") <= decimal(synthetic["maximumRatio"], "maximumRatio") <= Decimal(1):
            raise ReviewStop("NEEDS_INPUT", "rules.syntheticPolicy", "unsupported original synthetic policy")
    return {"b_mm": b, "h_mm": h, "Ec_MPa": ec, "eps_top": eps, "layers": normalized_layers,
        "demand_Nmm": moment, "demandBasis": demand["basis"], "compressionFace": scope["compressionFace"],
        "forceTolerance_N": force_tol, "depthTolerance_mm": depth_tol, "maxIterations": solver["maxIterations"],
        "independentRelativeTolerance": relative_tol, "displayDecimals": solver["displayDecimals"],
        "conversions": trace, "model": MODEL, "assumptions": ASSUMPTIONS}


def response_at_depth(data, c):
    compression = data["b_mm"] * data["Ec_MPa"] * data["eps_top"] * c / 2
    steel = []
    for layer in data["layers"]:
        strain = data["eps_top"] * (layer["depth_mm"] / c - 1)
        elastic_stress = layer["Es_MPa"] * strain
        stress = max(-layer["fy_MPa"], min(layer["fy_MPa"], elastic_stress))
        steel.append({"strain_tension_positive": strain, "stress_MPa": stress, "force_N": layer["area_mm2"] * stress,
            "sign": "near_zero" if abs(stress) <= 1e-8 else "tension" if strain > 0 else "compression",
            "state": "yield_boundary" if abs(abs(elastic_stress)-layer["fy_MPa"]) <= 1e-8 else "yielded" if abs(elastic_stress) > layer["fy_MPa"] else "elastic"})
    residual = compression - sum(layer["force_N"] for layer in steel)
    moment = sum(s["force_N"] * layer["depth_mm"] for s, layer in zip(steel, data["layers"])) - compression * c / 3
    return {"neutralAxis_mm": c, "concreteCompression_N": compression, "concreteCentroid_mm": c / 3,
        "concreteTopStress_MPa": data["Ec_MPa"] * data["eps_top"], "steel": steel,
        "residual_N": residual, "modelMoment_Nmm": moment}


def solve(data):
    lower, upper = 0.0, data["h_mm"]
    if response_at_depth(data, upper)["residual_N"] <= 0:
        raise ReviewStop("OUT_OF_SCOPE", "neutralAxis", "equilibrium outside the supported partial-compression section")
    trace = []
    for iteration in range(1, data["maxIterations"] + 1):
        depth = (lower + upper) / 2
        result = response_at_depth(data, depth)
        trace.append({"iteration": iteration, "lower_mm": lower, "upper_mm": upper,
            "depth_mm": depth, "residual_N": result["residual_N"]})
        if abs(result["residual_N"]) <= data["forceTolerance_N"] and upper - lower <= data["depthTolerance_mm"]:
            if result["modelMoment_Nmm"] <= 0 or not math.isfinite(result["modelMoment_Nmm"]):
                raise ReviewStop("OUT_OF_SCOPE", "moment", "positive finite prescribed-strain response required")
            return {**result, "status": "MECHANICS_ONLY", "method": "bounded_bisection", "trace": trace,
                "model": MODEL, "iterations": iteration}
        if result["residual_N"] > 0:
            if upper == depth:
                break
            upper = depth
        else:
            if lower == depth:
                break
            lower = depth
    raise ReviewStop("HUMAN_REVIEW_REQUIRED", "solver", "NONCONVERGENCE: both force and depth tolerances not reached within maxIterations or floating-point progress ceased", {"trace": trace})
