// Package risk implements Mosca's Theorem and severity classification.
package risk

// MoscaParams captures inputs to the X+Y-Z formula.
type MoscaParams struct {
	X int // data shelf-life in years
	Y int // migration time in years
	Z int // threat timeline in years (CRQC arrival)
}

// IndianBFSIDefaults follows the spec's per-service-category table.
var IndianBFSIDefaults = map[string]MoscaParams{
	// Financial transaction data — long-lived, severe
	"rds":        {X: 10, Y: 2, Z: 3},
	"aurora":     {X: 10, Y: 2, Z: 3},
	"dynamodb":   {X: 10, Y: 2, Z: 3},
	"redshift":   {X: 10, Y: 2, Z: 3},
	"qldb":       {X: 10, Y: 2, Z: 3},
	"timestream": {X: 10, Y: 2, Z: 3},

	// Customer PII / secrets — high
	"s3":             {X: 7, Y: 2, Z: 3},
	"backup":         {X: 7, Y: 2, Z: 3},
	"secretsmanager": {X: 7, Y: 2, Z: 3},
	"ssm":            {X: 7, Y: 2, Z: 3},
	"glue":           {X: 7, Y: 2, Z: 3},
	"sagemaker":      {X: 7, Y: 2, Z: 3},
	"opensearch":     {X: 7, Y: 2, Z: 3},
	"documentdb":     {X: 7, Y: 2, Z: 3},
	"keyspaces":      {X: 7, Y: 2, Z: 3},
	"neptune":        {X: 7, Y: 2, Z: 3},
	"workspaces":     {X: 7, Y: 2, Z: 3},
	"efs":            {X: 7, Y: 2, Z: 3},
	"fsx":            {X: 7, Y: 2, Z: 3},
	"ebs":            {X: 7, Y: 2, Z: 3},

	// Session / ephemeral — low
	"elasticache":    {X: 1, Y: 1, Z: 3},
	"memorydb":       {X: 1, Y: 1, Z: 3},
	"sqs":            {X: 1, Y: 1, Z: 3},
	"sns":            {X: 1, Y: 1, Z: 3},
	"kinesis":        {X: 1, Y: 1, Z: 3},
	"cloudwatchlogs": {X: 3, Y: 1, Z: 3},
	"msk":            {X: 3, Y: 1, Z: 3},
	"lightsail":      {X: 3, Y: 1, Z: 3},
	"dms":            {X: 3, Y: 1, Z: 3},

	// Certificates — medium
	"acm":              {X: 5, Y: 1, Z: 3},
	"acmpca":           {X: 5, Y: 1, Z: 3},
	"iam_certs":        {X: 5, Y: 1, Z: 3},
	"cloudfront_certs": {X: 5, Y: 1, Z: 3},
	"iot_certs":        {X: 5, Y: 1, Z: 3},

	// TLS in-transit — high (HNDL exposure)
	"alb":               {X: 7, Y: 1, Z: 3},
	"nlb":               {X: 7, Y: 1, Z: 3},
	"apigw_rest":        {X: 7, Y: 1, Z: 3},
	"apigw_http":        {X: 7, Y: 1, Z: 3},
	"cloudfront":        {X: 7, Y: 1, Z: 3},
	"appsync":           {X: 7, Y: 1, Z: 3},
	"iotcore":           {X: 7, Y: 1, Z: 3},
	"transferfamily":    {X: 7, Y: 1, Z: 3},
	"vpn":               {X: 7, Y: 1, Z: 3},
	"directconnect":     {X: 7, Y: 1, Z: 3},
	"globalaccelerator": {X: 7, Y: 1, Z: 3},
	"eks":               {X: 5, Y: 1, Z: 3},
	"ecs":               {X: 5, Y: 1, Z: 3},
	"lambda":            {X: 5, Y: 1, Z: 3},

	// Key management
	"kms":      {X: 7, Y: 2, Z: 3},
	"cloudhsm": {X: 7, Y: 2, Z: 3},
}

// DefaultParams returns the default Mosca params for a given service identifier.
// Falls back to a 5/1/3 baseline when unknown.
func DefaultParams(service string) MoscaParams {
	if p, ok := IndianBFSIDefaults[service]; ok {
		return p
	}
	return MoscaParams{X: 5, Y: 1, Z: 3}
}

// NOTE: a dead CategoryFor helper (zero callers) was deleted: its
// default-to-CategoryDataAtRest branch would have assigned a definite category
// to services it did not know (e.g. signing surfaces), a latent
// verdict-honesty hazard if ever wired. Category assignment lives with the
// scanners/taxonomy, which know their own category.
