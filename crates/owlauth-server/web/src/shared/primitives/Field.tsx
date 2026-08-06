import { cloneElement, forwardRef, useId } from "react";
import type {
  InputHTMLAttributes,
  ReactElement,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from "react";

import styles from "./primitives.module.css";

interface FieldControlProps {
  readonly "aria-describedby"?: string | undefined;
  readonly "aria-errormessage"?: string | undefined;
  readonly "aria-invalid"?: boolean | "true" | "false" | undefined;
}

interface FieldProps {
  readonly label: string;
  readonly htmlFor: string;
  readonly description?: ReactNode;
  readonly error?: string | null;
  readonly optional?: boolean;
  readonly children: ReactElement<FieldControlProps>;
}

export function Field({
  label,
  htmlFor,
  description,
  error,
  optional = false,
  children,
}: FieldProps) {
  const generatedId = useId();
  const descriptionId = `${generatedId}-description`;
  const errorId = `${generatedId}-error`;
  const hasError = error !== undefined && error !== null;
  const describedBy = [
    children.props["aria-describedby"],
    description === undefined ? undefined : descriptionId,
  ]
    .filter((value): value is string => value !== undefined && value.length > 0)
    .join(" ");
  const control = cloneElement(children, {
    "aria-describedby": describedBy === "" ? undefined : describedBy,
    "aria-errormessage": hasError ? errorId : children.props["aria-errormessage"],
    "aria-invalid": hasError ? true : children.props["aria-invalid"],
  });
  return (
    <div className={styles["field"]}>
      <label className={styles["label"]} htmlFor={htmlFor}>
        {label}
        {optional ? " (optional)" : ""}
      </label>
      {control}
      {description === undefined ? null : (
        <p id={descriptionId} className={styles["description"]}>
          {description}
        </p>
      )}
      {hasError ? (
        <p id={errorId} className={styles["fieldError"]} role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  function Input(props, ref) {
    return <input {...props} ref={ref} className={join(styles["input"], props.className)} />;
  },
);

export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={join(styles["select"], props.className)} />;
}

export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={join(styles["textarea"], props.className)} />;
}

interface CheckboxProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "type"> {
  readonly children: ReactNode;
}

export function Checkbox({ children, ...props }: CheckboxProps) {
  return (
    <label className={styles["checkbox"]}>
      <input {...props} type="checkbox" />
      <span>{children}</span>
    </label>
  );
}

interface FormErrorSummaryProps {
  readonly title?: string;
  readonly errors: readonly string[];
}

export function FormErrorSummary({ title = "Check the form", errors }: FormErrorSummaryProps) {
  const headingId = useId();
  if (errors.length === 0) return null;
  return (
    <div className={join(styles["alert"], styles["alertDanger"])} role="alert" tabIndex={-1}>
      <span aria-hidden="true">!</span>
      <div>
        <strong id={headingId}>{title}</strong>
        <ul aria-labelledby={headingId}>
          {errors.map((error) => (
            <li key={error}>{error}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function join(base: string | undefined, extra: string | undefined): string {
  return [base, extra].filter(Boolean).join(" ");
}
