// Generate src/policy.ts from ../../agentforge.schema.json.
// With --check, fail if the committed file differs (CI drift check, T11.1).
import { readFile, writeFile } from "node:fs/promises";
import { compile } from "json-schema-to-typescript";

const here = new URL("..", import.meta.url);
const schemaUrl = new URL("../../../agentforge.schema.json", import.meta.url);
const outUrl = new URL("src/policy.ts", here);

const schema = JSON.parse(await readFile(schemaUrl, "utf8"));
const banner =
  "/* Generated from agentforge.schema.json by scripts/generate.mjs. Do not edit. */\n" +
  "/* Regenerate: pnpm --filter @agentforge/policy-types generate */";
const ts = await compile(schema, "Policy", {
  bannerComment: banner,
  additionalProperties: false,
  unreachableDefinitions: false,
  style: { singleQuote: false, semi: true, printWidth: 100 },
});

if (process.argv.includes("--check")) {
  const current = await readFile(outUrl, "utf8").catch(() => "");
  if (current !== ts) {
    console.error("src/policy.ts is stale; run `pnpm --filter @agentforge/policy-types generate`");
    process.exit(1);
  }
  console.log("policy types are up to date");
} else {
  await writeFile(outUrl, ts);
  console.log("wrote src/policy.ts");
}
