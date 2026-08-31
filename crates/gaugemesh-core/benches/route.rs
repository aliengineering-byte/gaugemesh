use criterion::{Criterion, criterion_group, criterion_main};
use gaugemesh_core::route::{
    ConstraintResult, RouteCandidate, RouteId, RouteMetricSnapshot, RouteWeights, plan,
};

fn plan_sixteen_routes(criterion: &mut Criterion) {
    let candidates = (0..16)
        .map(|index| RouteCandidate {
            route_id: RouteId(format!("route-{index:02}")),
            endpoint_id: format!("endpoint-{index:02}"),
            hard_constraints: ConstraintResult {
                allowed: true,
                rejections: vec![],
            },
            metrics: RouteMetricSnapshot {
                latency: 10 + index,
                cost: index,
                failure: index % 3,
                pressure: index % 5,
                exposure: 0,
                switching: u32::from(index != 0),
            },
            semantic_loss: 0,
        })
        .collect::<Vec<_>>();
    let weights = RouteWeights {
        latency: 10,
        cost: 30,
        failure: 30,
        semantic_loss: 1_000,
        pressure: 20,
        exposure: 50,
        switching: 10,
    };
    criterion.bench_function("plan_16_routes", |bencher| {
        bencher.iter(|| plan(candidates.clone(), weights).expect("route exists"));
    });
}

criterion_group!(benches, plan_sixteen_routes);
criterion_main!(benches);
