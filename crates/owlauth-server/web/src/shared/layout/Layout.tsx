import type { ReactNode, RefObject } from "react";

import styles from "./layout.module.css";

interface PageHeaderProps {
  readonly title: string;
  readonly description?: ReactNode;
  readonly status?: ReactNode;
  readonly actions?: ReactNode;
  readonly headingRef?: RefObject<HTMLHeadingElement | null>;
}

export function PageHeader({ title, description, status, actions, headingRef }: PageHeaderProps) {
  return (
    <header className={styles["pageHeader"]}>
      <div>
        <div className={styles["pageTitleRow"]}>
          <h1 ref={headingRef} tabIndex={-1}>
            {title}
          </h1>
          {status}
        </div>
        {description === undefined ? null : <p>{description}</p>}
      </div>
      {actions === undefined ? null : <div className={styles["pageActions"]}>{actions}</div>}
    </header>
  );
}

interface BreadcrumbsProps {
  readonly children: ReactNode;
  readonly label?: string;
}

export function Breadcrumbs({ children, label = "Breadcrumb" }: BreadcrumbsProps) {
  return (
    <nav className={styles["breadcrumbs"]} aria-label={label}>
      <ol>{children}</ol>
    </nav>
  );
}

interface DataTableProps {
  readonly caption: string;
  readonly headings: readonly string[];
  readonly children: ReactNode;
}

export function DataTable({ caption, headings, children }: DataTableProps) {
  return (
    // Scroll regions must be keyboard-focusable when their overflow is not otherwise reachable.
    // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
    <div className={styles["tableRegion"]} role="region" aria-label={caption} tabIndex={0}>
      <p className={styles["tableScrollHint"]}>Scroll horizontally to review all columns.</p>
      <table className={styles["table"]}>
        <caption className="visually-hidden">{caption}</caption>
        <thead>
          <tr>
            {headings.map((heading) => (
              <th key={heading} scope="col">
                {heading}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

interface LoadingStateProps {
  readonly children: ReactNode;
}

export function LoadingState({ children }: LoadingStateProps) {
  return (
    <div className={styles["loading"]} role="status">
      <span className={styles["loadingIndicator"]} aria-hidden="true" />
      <span>{children}</span>
    </div>
  );
}

interface EmptyStateProps {
  readonly title: string;
  readonly description: ReactNode;
  readonly action?: ReactNode;
  readonly level?: 1 | 2 | 3;
  readonly headingRef?: RefObject<HTMLHeadingElement | null>;
}

export function EmptyState({ title, description, action, level = 2, headingRef }: EmptyStateProps) {
  const Heading = level === 1 ? "h1" : level === 2 ? "h2" : "h3";
  return (
    <div className={styles["empty"]}>
      <Heading
        ref={headingRef}
        {...(level === 1 || headingRef !== undefined ? { tabIndex: -1 } : {})}
      >
        {title}
      </Heading>
      <p>{description}</p>
      {action}
    </div>
  );
}

interface DescriptionItem {
  readonly term: string;
  readonly detail: ReactNode;
}

export function DescriptionList({ items }: { readonly items: readonly DescriptionItem[] }) {
  return (
    <dl className={styles["descriptionList"]}>
      {items.map((item) => (
        <Fragment key={item.term} item={item} />
      ))}
    </dl>
  );
}

function Fragment({ item }: { readonly item: DescriptionItem }) {
  return (
    <>
      <dt>{item.term}</dt>
      <dd>{item.detail}</dd>
    </>
  );
}

export function Tabs({
  children,
  label,
}: {
  readonly children: ReactNode;
  readonly label: string;
}) {
  return (
    <nav className={styles["tabs"]} aria-label={label}>
      {children}
    </nav>
  );
}

export function tabClassName(): string {
  return styles["tab"] ?? "";
}

interface SectionProps {
  readonly title: string;
  readonly description?: ReactNode;
  readonly action?: ReactNode;
  readonly children: ReactNode;
  readonly level?: 2 | 3;
}

export function Section({ title, description, action, children, level = 2 }: SectionProps) {
  const Heading = level === 2 ? "h2" : "h3";
  return (
    <section className={styles["section"]}>
      <header className={styles["sectionHeader"]}>
        <div>
          <Heading>{title}</Heading>
          {description === undefined ? null : <p>{description}</p>}
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}
