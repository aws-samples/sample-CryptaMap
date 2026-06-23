// Thin re-export of the generated roadmap types, kept at this path so the
// dashboard's existing `import ... from '../types/roadmap'` sites are unchanged.
//
// Source of truth: internal/roadmap/roadmap.go + internal/pqc/matrix.go,
// generated into ./generated.ts by `make generate-types` (cmd/gen-ts). DO NOT
// hand-edit these shapes — change the Go source and regenerate.
//
// Wire-key reminders preserved by the generator:
//   - top-level keys are lowercase: asOf, generatedFrom, items, byService, byAccount
//   - RoadmapItem.ExposureFlag (Go) serializes as the JSON key "hndlExposed"

export type {
  PQCStatus,
  UpgradeEase,
  Confidence,
  SymmetricStrength,
  RoadmapItem,
  ServiceRollup,
  AccountRollup,
  Roadmap,
} from './generated';
