# Optional section mechanics review

Define the task. Execute it under controls. Inspect the result.

This is a separate Python-standard-library consumer of GaugeMesh's public MCP
Tasks/Run interface, not a solver inside the gateway. It reviews an explicitly
supplied, educational, nonprestressed rectangular beam section in uniaxial
flexure. It neither derives loads nor checks a real project's code compliance.
No publisher formula, coefficient, normative table or worked example is included.

## First use

Use Linux x64, Python 3.12+, the source from the corresponding public release
tag, and its downloaded, checksum/attestation-verified binary. Rust is unnecessary.
The output directory must be new, absolute, owned by you, and on a drive with
space. Review `educational.json` and the assumptions below before opting in:

```sh
python3 examples/concrete_review/review.py run --binary /absolute/path/gaugemesh --request examples/concrete_review/educational.json --output /new/absolute/review --accept-assumptions
```

Inspect `report.html` or `report.md`, `report.json`, and `run-export.json`.
The HTML is self-contained, escaped, and has no scripts, remote resources or
automatic transmission. The optional feedback link sends nothing automatically;
sanitize private inputs and paths before choosing to share anything.

The four immutable steps are `input → calculate → synthetic → verify`. The plan
pins the request, provider interface, producer files, policies and artifact root.
Each is an ordinary public Task with one attempt. A required accepted artifact
must precede the next step. The domain worker has fixed stages, not arbitrary
command evaluation. It is trusted local code, not an OS sandbox.

To observe a genuine durable checkpoint, add `--pause-after-input` to the first
command. The gateway and its provider stop after the accepted input artifact;
calculation has not started. Continue the same Run, without repeating input:

```sh
python3 examples/concrete_review/review.py resume --binary /absolute/path/gaugemesh --output /new/absolute/review
```

After completion, independently recheck accepted files, Run integrity, numerical
values and report bindings without starting a gateway/provider or doing effects:

```sh
python3 examples/concrete_review/review.py verify --binary /absolute/path/gaugemesh --output /new/absolute/review
```

Keep the original root, export and exact producer source bytes. Hashes are
recomputable integrity checks, **not signatures or authenticity proofs**. A changed
producer/request/plan is refused, not silently upgraded. Completed resume uses
offline verification only. Ambiguous mid-effect execution must not be replayed;
the inherited public Run uncertainty policy is stop/reconcile. This example
qualifies checkpoint recovery, not arbitrary provider-session persistence.

## Input and units

`educational.json` is an original synthetic fixture, not a real project, owner
approval or a publisher example. Every field is explicit; missing, conflicting,
duplicate, nonfinite, out-of-range and unsupported fields are refused. No assumed
load factors, dimensions, reinforcement positions, material strengths or code
editions fill gaps. The CLI assumption opt-in and exact JSON model approval are
both required. Correct refused input in a **new** output directory.

Quantities use `{ "value": "decimal string", "unit": "mm" }`, not bare numbers.
Declare either SI or US consistently. Length: mm/m or in/ft; area: mm2 or in2;
stress: MPa/GPa or psi/ksi; force: N/kN or lbf/kip; moment: N*mm/kN*m or
lbf*in/kip*ft; strain: 1. Dimensions and unit system are checked independently.
The report preserves original values, conversion factors, normalized decimal
values and units. Normalization uses 28-significant-digit Decimal arithmetic;
the primary computation then uses binary64. Extremely small nonzero values are
refused before arithmetic could turn them into zero.

Dimensional conversions use inch = 25.4 mm and
lbf = 0.45359237 kg × 9.80665 m/s² = 4.4482216152605 N. These are unit definitions,
not design coefficients. The psi/ksi quotient has finite Decimal precision.
See the [NIST SI conversion guide](https://www.nist.gov/pml/special-publication-811/nist-guide-si-appendix-b-conversion-factors/nist-guide-si-appendix-b8).
The US fixture independently derives these conversions without using the
implementation's unit table.

The only project profile implemented is `EDUCATIONAL_NO_JURISDICTION`, with an
explicit confirmation source, no governing code/amendments/reference adoption,
and no normative errata. Top or bottom compression must be stated; layer depths
are always measured from that face. One or two layers lie strictly inside the
rectangle. Axial force and torsion must be exactly zero. Prestress, nonrectangular
sections, unusual material models and other member types are refused.
Bounds are computational limits, not statements of physical applicability.

## Original model and independent calculation

The caller supplies b, h, every steel area A and depth d, Ec, Es, fy, prescribed
top compression strain e, and supplied moment with SERVICE or FACTORED basis.
The basis is a label: **no load or resistance factors are applied**.

The declared model assumes plane sections, no concrete tension, linear concrete
compression, elastic-perfectly-plastic steel, and no subtraction for displaced
concrete at steel. The prescribed top strain is **not a code limit or crushing
criterion**. These assumptions are not automatically appropriate to real concrete.

For partial compression depth c between 0 and h:

- Concrete resultant C = b Ec e c / 2, acting at c/3 from the compression face.
- Tension-positive steel strain = e(d/c − 1); stress is Es times strain, clipped
  to the caller's ±fy. Force T = A × stress. Yielding is calculated, not assumed.
- Axial equilibrium: C − ΣT = 0. Section moment response M = Σ(Td) − Cc/3.

The primary solver uses bounded bisection and requires **both** the caller's
force and depth tolerances. It retains every bracket/residual and refuses
nonconvergence or floating-point stagnation. Iterations are capped at 128.

The independent oracle imports no primary numerical helper. With 60-digit
Decimal arithmetic it enumerates each layer's elastic / positive-yield /
negative-yield state. Define K = b Ec e / 2, Y = Σ(yielded sign × A fy),
E = Σ(elastic A Es e), D = Σ(elastic A Es e d). Each active set solves
Kc² + (E−Y)c − D = 0 algebraically; it must satisfy its stress inequalities,
0 < c < h, and a unique root after yield-boundary deduplication. An alternative
moment identity Σ[T(d−c)] + 2Kc²/3 is checked. The verifier checks layer count,
forces, strains, stresses, signs and regimes, concrete resultant/centroid/top
stress, moment, equilibrium and bounded convergence trace—not just the final M.
`yield_boundary` means a stress boundary, not a claim about prior plastic history.

Original analytic fixtures (mm, mm2, MPa, N*mm), all b=300, h=800, Ec=20000,
Es=200000; layers are (A,d,fy):

| e | Layers | c | M | Steel stress |
| --- | --- | --- | --- | --- |
| .001 | (1500,600,500) | 200 | 320000000 | 400 |
| .001 | (1500,600,300) | 150 | 247500000 | 300 |
| .001 | (1600,600,500); (400,100,500) | 200 | 340000000 | 400; −100 |
| .003 | (10000,600,200); (1000,50,200) | 200 | 1070000000 | 200; −200 |
| .001 | (1500,600,500); (400,200,500) | 200 | 320000000 | 400; 0 |
| .001 | (1500,600,400) | 200 | 320000000 | 400 at boundary |

Display precision is separate from convergence. Demand comparison uses unrounded
values and the explicit numerical band 4 × forceTolerance × h + relativeTolerance
× |M|; inside it the result is INDETERMINATE_NUMERICAL_TOLERANCE. It is a comparison
to the declared prescribed-strain response, not a design capacity. No acceptance
rounding or hidden reduction factor is used.

## Catalog, rights and coverage

```sh
python3 examples/concrete_review/review.py catalog
```

`catalog.json` records official public metadata for ACI CODE-318-25,
SPEC-301-20, SPEC-117-10 (reapproved 2015), CODE-562-25 and ASCE/SEI 7-22.
The ASCE page listed Supplements 1–3 and errata; the ACI errata index was observed.
No normative text, errata or supplement content was downloaded, applied or used
to infer jurisdictional adoption. ASCE is loads context, not concrete resistance.

Reading, automated processing, AI use, derived implementation, redistribution
and model-provider transmission are separate rights. None is inferred from
purchase, possession, a citation or metadata. The
[ACI AI policy](https://www.concrete.org/newsandevents/news/newsdetail.aspx?f=51751802)
and [ASCE terms](https://www.asce.org/about-asce/terms-conditions/) require the
appropriate written authorization for restricted uses. See
[the unsent permission requirements](permissions-required.md). No paywall was
bypassed, account created, rights request sent or material purchased.

| Capability | Implemented boundary |
| --- | --- |
| Official catalog | Metadata only; adoption and normative errata NOT_ASSESSED |
| Mechanics | Original declared equilibrium, independently verified |
| Optional synthetic policy | SYNTHETIC_MODEL_DEMAND_MARGIN/1; caller-supplied ratio, no standard authority |
| Authorized standards rules | Empty set; SOURCE_AUTHORIZATION_REQUIRED |
| Unsupported edition | OUT_OF_SCOPE; no fallback or edition mixing |
| Nonconvergence | HUMAN_REVIEW_REQUIRED; numerical verification NOT_EVALUATED |

A Run may correctly complete a declared nonconvergence report. Run `verified`
means execution/artifact policies passed, not that mechanics were verified.
Only an independently checked converged calculation gets numerical VERIFIED.

Shear, development/anchorage, cover/spacing, deflection, durability, fire,
stability, seismic detailing, construction quality, system behavior, crushing,
material-model applicability, load derivation, code capacity and compliance are
all **NOT_EVALUATED**. No safe/compliant/approved label is produced. Qualified
professional and applicable-authority review remains necessary for real use.

## Executable qualification

```sh
python3 -m unittest discover -s examples/concrete_review -p 'test_*.py' -v
python3 examples/concrete_review/qualify.py --binary /absolute/path/gaugemesh --output /new/absolute/qualification
```

The suite preserves raw protocol, worker start/effect counts, accepted artifacts,
commands, reports and cleanup observations. It covers independent analytical and
unit cases, tension/compression/yield boundaries, layer permutation and geometric
similarity, unrounded comparison boundaries, refusals, nonconvergence, actual
checkpoint stop/resume without a duplicate input step, offline-only completion,
and artifact/report/frozen-input tamper rejection. Test-created tampered files
are restored from their retained original bytes; user files are not overwritten.
Source-built qualification is distinct from the release workflow's fresh public
download/attestation/checksum qualification. Windows Run execution is unsupported;
Linux x64 is this consumer's qualified platform. No production benchmark or
structural certification is claimed.
