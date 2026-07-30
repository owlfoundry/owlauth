import jsxA11y from "eslint-plugin-jsx-a11y";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

const typedRules = {
  ...reactHooks.configs.flat["recommended-latest"].rules,
  ...jsxA11y.flatConfigs.strict.rules,
  "@typescript-eslint/consistent-type-imports": ["error", { prefer: "type-imports" }],
};

export default tseslint.config(
  {
    ignores: ["dist/**", "node_modules/**", "src/generated/*-openapi.ts"],
  },
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      "jsx-a11y": jsxA11y,
      "react-hooks": reactHooks,
    },
    rules: typedRules,
  },
  {
    files: ["src/runtime/**/*.{ts,tsx}"],
    rules: {
      "@typescript-eslint/no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["**/control/**", "**/control-openapi"],
              message: "Runtime cannot import Control authority.",
            },
          ],
        },
      ],
    },
  },
  {
    files: ["src/control/**/*.{ts,tsx}"],
    rules: {
      "@typescript-eslint/no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["**/runtime/**", "**/runtime-openapi"],
              message: "Control cannot import Runtime authority.",
            },
          ],
        },
      ],
    },
  },
  {
    files: ["browser-tests/**/*.ts"],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    files: ["scripts/**/*.mjs", "eslint.config.js", "*.config.ts"],
    ...tseslint.configs.disableTypeChecked,
  },
);
