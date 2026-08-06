import { useId, useState } from "react";

import { PlusIcon, TrashIcon } from "../icons/Icons";
import { Button } from "../primitives/Button";
import { Input } from "../primitives/Field";
import styles from "./compositions.module.css";

interface StringListFieldProps {
  readonly label: string;
  readonly description: string;
  readonly values: readonly string[];
  readonly onChange: (values: string[]) => void;
  readonly type?: "url" | "text";
  readonly itemLabel?: string;
  readonly placeholder?: string;
  readonly required?: boolean;
  readonly disabled?: boolean;
  readonly validate?: (value: string) => string | null;
}

export function StringListField({
  label,
  description,
  values,
  onChange,
  type = "url",
  itemLabel = "Value",
  placeholder,
  required = false,
  disabled = false,
  validate,
}: StringListFieldProps) {
  const id = useId();
  const [announcement, setAnnouncement] = useState("");
  const normalizedValues = values.length === 0 ? [""] : values;
  const duplicateValues = duplicates(normalizedValues);

  function update(index: number, value: string) {
    const next = [...normalizedValues];
    const pasted = value
      .split(/\r?\n/u)
      .map((item) => item.trim())
      .filter(Boolean);
    if (pasted.length > 1) {
      next.splice(index, 1, ...pasted);
      setAnnouncement(`${String(pasted.length)} items added from pasted text.`);
    } else {
      next[index] = value;
    }
    onChange(next);
  }

  function add() {
    onChange([...normalizedValues, ""]);
    setAnnouncement("Item added.");
  }

  function remove(index: number) {
    const next = normalizedValues.filter((_, itemIndex) => itemIndex !== index);
    onChange(next.length === 0 ? [""] : next);
    setAnnouncement("Item removed.");
  }

  return (
    <fieldset className={styles["listField"]} aria-describedby={`${id}-description`}>
      <legend>{label}</legend>
      <p id={`${id}-description`} className={styles["fieldDescription"]}>
        {description}
      </p>
      <div className={styles["listRows"]}>
        {normalizedValues.map((value, index) => {
          const trimmed = value.trim();
          const error =
            trimmed !== "" && duplicateValues.has(trimmed)
              ? "This value is already in the list."
              : trimmed !== "" && validate !== undefined
                ? validate(trimmed)
                : null;
          const inputId = `${id}-${String(index)}`;
          const errorId = `${inputId}-error`;
          return (
            <div className={styles["listRow"]} key={String(index)}>
              <label className="visually-hidden" htmlFor={inputId}>
                {itemLabel} {String(index + 1)}
              </label>
              <Input
                id={inputId}
                type={type}
                value={value}
                placeholder={placeholder}
                required={
                  required &&
                  normalizedValues.every(
                    (candidate, candidateIndex) =>
                      candidateIndex === index || candidate.trim() === "",
                  )
                }
                disabled={disabled}
                aria-invalid={error === null ? undefined : true}
                aria-errormessage={error === null ? undefined : errorId}
                onChange={(event) => {
                  update(index, event.target.value);
                }}
              />
              <Button
                type="button"
                variant="quiet"
                iconOnly
                disabled={disabled}
                aria-label={`Remove ${itemLabel.toLowerCase()} ${String(index + 1)}`}
                onClick={() => {
                  remove(index);
                }}
              >
                <TrashIcon />
              </Button>
              {error === null ? null : (
                <p id={errorId} className={styles["rowError"]} role="alert">
                  {error}
                </p>
              )}
            </div>
          );
        })}
      </div>
      <Button type="button" variant="secondary" disabled={disabled} onClick={add}>
        <PlusIcon /> Add {itemLabel.toLowerCase()}
      </Button>
      <span className="visually-hidden" aria-live="polite">
        {announcement}
      </span>
    </fieldset>
  );
}

export function compactStringList(values: readonly string[]): string[] {
  return values.map((value) => value.trim()).filter(Boolean);
}

export function isValidStringList(values: readonly string[], required = false): boolean {
  const compact = compactStringList(values);
  return (!required || compact.length > 0) && new Set(compact).size === compact.length;
}

function duplicates(values: readonly string[]): Set<string> {
  const seen = new Set<string>();
  const repeated = new Set<string>();
  for (const value of values) {
    const trimmed = value.trim();
    if (trimmed === "") continue;
    if (seen.has(trimmed)) repeated.add(trimmed);
    seen.add(trimmed);
  }
  return repeated;
}
