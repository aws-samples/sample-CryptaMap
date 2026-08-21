package agent

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"sort"

	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/internal/roadmap"
	"github.com/aws-samples/cryptamap/internal/taxonomy"
)

// AssetView is a flattened, taxonomy-enriched projection of one
// models.CryptoAsset, joined to its roadmap PQC status by bom-ref — the exact
// same join dashboard/src/lib/assetRows.ts performs in TypeScript, mirrored
// here in Go so the agent's answers can never diverge from what the Assets
// page itself shows.
type AssetView struct {
	BomRef         string `json:"bomRef"`
	DisplayName    string `json:"displayName"`
	Service        string `json:"service"` // raw scanner id — join/filter key, not for display
	ResourceID     string `json:"resourceId"`
	ResourceARN    string `json:"resourceArn,omitempty"`
	AccountID      string `json:"accountId"`
	Region         string `json:"region"`
	AWSCategory    string `json:"awsCategory"`
	CryptoFunction string `json:"cryptoFunction"`
	Posture        string `json:"posture"`
	PQCStatus      string `json:"pqcStatus,omitempty"`
}

// Corpus is the in-memory, read-only snapshot of one `cryptamap serve`
// process's scan data. It is loaded once at server startup — the underlying
// CBOM/roadmap files do not change for the life of one serve run, the same
// assumption the rest of cmd/cryptamap/serve.go already makes — and shared
// across every /api/agent/chat request.
type Corpus struct {
	Assets  []AssetView
	Roadmap roadmap.Roadmap
}

// LoadCorpus loads the corpus from on-disk CBOM + roadmap files (the --dir /
// real-scan path).
func LoadCorpus(cbomPath, roadmapPath string) (*Corpus, error) {
	cbomRaw, err := os.ReadFile(cbomPath)
	if err != nil {
		return nil, fmt.Errorf("read CBOM: %w", err)
	}
	roadmapRaw, err := os.ReadFile(roadmapPath)
	if err != nil {
		return nil, fmt.Errorf("read roadmap: %w", err)
	}
	return buildCorpus(cbomRaw, roadmapRaw)
}

// LoadCorpusFS loads the corpus from an fs.FS (used for `cryptamap serve
// --demo`'s embedded webdist files, which os.ReadFile cannot open).
func LoadCorpusFS(fsys fs.FS, cbomPath, roadmapPath string) (*Corpus, error) {
	cbomRaw, err := fs.ReadFile(fsys, cbomPath)
	if err != nil {
		return nil, fmt.Errorf("read embedded CBOM: %w", err)
	}
	roadmapRaw, err := fs.ReadFile(fsys, roadmapPath)
	if err != nil {
		return nil, fmt.Errorf("read embedded roadmap: %w", err)
	}
	return buildCorpus(cbomRaw, roadmapRaw)
}

func buildCorpus(cbomRaw, roadmapRaw []byte) (*Corpus, error) {
	// output.ParseCBOM is the same pure reconstruction internal/output uses to
	// re-ingest a CBOM file — it reuses pkg/models.CryptoAsset rather than a
	// new ad hoc parser, so the agent's view of an asset can never drift from
	// the rest of the codebase's.
	scans, err := output.ParseCBOM(cbomRaw)
	if err != nil {
		return nil, fmt.Errorf("parse CBOM: %w", err)
	}

	var rm roadmap.Roadmap
	if err := json.Unmarshal(roadmapRaw, &rm); err != nil {
		return nil, fmt.Errorf("parse roadmap: %w", err)
	}

	pqcByRef := make(map[string]string, len(rm.Items))
	for _, item := range rm.Items {
		if item.AssetBomRef != "" {
			pqcByRef[item.AssetBomRef] = string(item.PQCStatus)
		}
	}

	var assets []AssetView
	for _, sr := range scans {
		for _, a := range sr.Assets {
			tax := taxonomy.MustLookup(a.Service)
			posture := a.Properties["posture"]
			if posture == "" {
				posture = "unknown"
			}
			assets = append(assets, AssetView{
				BomRef:         a.BomRef,
				DisplayName:    tax.DisplayName,
				Service:        a.Service,
				ResourceID:     a.ResourceID,
				ResourceARN:    a.ResourceARN,
				AccountID:      a.AccountID,
				Region:         a.Region,
				AWSCategory:    tax.AWSCategory,
				CryptoFunction: tax.CryptoFunction,
				Posture:        posture,
				PQCStatus:      pqcByRef[a.BomRef],
			})
		}
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].BomRef < assets[j].BomRef })

	return &Corpus{Assets: assets, Roadmap: rm}, nil
}
