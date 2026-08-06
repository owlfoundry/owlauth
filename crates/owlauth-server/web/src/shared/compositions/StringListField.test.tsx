import { useState } from "react";
import { fireEvent, render, screen } from "@testing-library/react";

import { StringListField } from "./StringListField";

function RequiredListFixture() {
  const [values, setValues] = useState(["", "https://identity.example.test"]);
  return (
    <form aria-label="origin form">
      <StringListField
        label="Allowed origins"
        description="At least one origin is required."
        itemLabel="Origin"
        values={values}
        onChange={setValues}
        required
      />
      <button type="submit">Save</button>
    </form>
  );
}

test("required string lists accept a later non-empty row", () => {
  render(<RequiredListFixture />);

  const form = screen.getByRole("form", { name: "origin form" });
  expect(form).toBeValid();

  fireEvent.change(screen.getByLabelText("Origin 2", { exact: true }), { target: { value: "" } });
  expect(form).not.toBeValid();
});
