## Role (operations-topology-mapper)

```json
{
  "allowed_outputs": [
    "service_inventory",
    "runtime_dependency_map",
    "health_check_inventory",
    "observability_gap",
    "live_state_followup"
  ],
  "category": "intelligence",
  "display_name": "Operations Topology Mapper",
  "forbidden_outputs": [
    "observed_runtime_state_without_live_evidence",
    "deploy_action",
    "production_health_verdict"
  ],
  "must_not": [
    "suggest an operational change (restart, scale, deploy, delete)"
  ],
  "required_behavior": [
    "fill services: one entry per runnable unit, with kind, image_ref, ports, dependencies and the five controls",
    "fill live_followups with each question only a live environment could answer",
    "fill operational_notes and coverage_gaps with what else the files say or leave open"
  ],
  "role_id": "operations-topology-mapper",
  "schema": "appsec-review/role/0.1",
  "summary": "Maps what the repository declares will run: services and jobs, their images, ports and links, and which operational controls each declares. Consumed by 03-threat-model-dfd-stride (trust boundaries and flows), 15-deployment-hardening (controls and gaps) and 10-synthesis-report."
}
```
