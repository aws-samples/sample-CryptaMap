import BarChart from '@cloudscape-design/components/bar-chart';
import Box from '@cloudscape-design/components/box';

export interface BarDatum {
  /** Category label shown on the (horizontal) axis. */
  label: string;
  /** Assets flagged critical (no-encryption / legacy-tls). */
  critical: number;
  /** All remaining assets for this category. */
  other: number;
}

interface Props {
  data: BarDatum[];
  ariaLabel: string;
  xTitle: string;
  /** Horizontal bars read better for long category labels (services). */
  horizontal?: boolean;
}

// ServiceBar is a stacked Cloudscape BarChart used for both the by-service and
// by-crypto-function rollups on the Overview. Two stacked series — critical
// (red) and other (blue) — so critical exposure is visible per category.
export default function ServiceBar({ data, ariaLabel, xTitle, horizontal = true }: Props) {
  const series = [
    {
      title: 'Critical (no-encryption / legacy-TLS)',
      type: 'bar' as const,
      color: '#d63a3a',
      data: data.map((d) => ({ x: d.label, y: d.critical })),
    },
    {
      title: 'Other assets',
      type: 'bar' as const,
      color: '#3a7adb',
      data: data.map((d) => ({ x: d.label, y: d.other })),
    },
  ];

  return (
    <BarChart<string>
      series={series}
      stackedBars
      horizontalBars={horizontal}
      xScaleType="categorical"
      ariaLabel={ariaLabel}
      xTitle={xTitle}
      yTitle="Assets"
      hideFilter
      height={Math.max(220, data.length * (horizontal ? 34 : 0) + 80)}
      empty={
        <Box textAlign="center" color="text-status-inactive">
          No data to chart.
        </Box>
      }
    />
  );
}
