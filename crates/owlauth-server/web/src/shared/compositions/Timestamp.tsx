interface TimestampProps {
  readonly value: string | null | undefined;
  readonly empty?: string;
}

export function Timestamp({ value, empty = "Never" }: TimestampProps) {
  if (value === null || value === undefined || value === "") return <>{empty}</>;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return <>{value}</>;
  return (
    <time dateTime={value} title={value}>
      {parsed.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}
    </time>
  );
}
