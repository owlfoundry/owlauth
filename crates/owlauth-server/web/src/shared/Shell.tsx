import type { ReactNode } from "react";

import styles from "./shell.module.css";

export interface ShellProps {
  readonly eyebrow: string;
  readonly title: string;
  readonly children: ReactNode;
}

export function Shell({ eyebrow, title, children }: ShellProps) {
  return (
    <main className={styles["shell"]}>
      <section className={styles["card"]} aria-labelledby="page-title">
        <p className={styles["eyebrow"]}>{eyebrow}</p>
        <h1 id="page-title">{title}</h1>
        <div className={styles["content"]}>{children}</div>
      </section>
    </main>
  );
}
