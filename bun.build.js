// Build ESM + CJS bundles with Bun, targeting browsers.
const { rename, rm } = await import("fs/promises");

async function build() {
  // clean old build
  await rm("dist", { recursive: true }).catch(() => {});

  // ESM
  let esm = await Bun.build({
    entrypoints: ["src/index.ts"],
    outdir: "dist/esm",
    target: "browser",
    format: "esm",
    minify: true,
    sourcemap: "external"
  });
  if (!esm.success) {
    console.error("ESM build failed", esm.logs);
    process.exit(1);
  }

  // CJS (will emit dist/cjs/index.js -> rename to .cjs)
  let cjs = await Bun.build({
    entrypoints: ["src/index.ts"],
    outdir: "dist/cjs",
    target: "browser",
    format: "cjs",
    minify: true,
    sourcemap: "external"
  });
  if (!cjs.success) {
    console.error("CJS build failed", cjs.logs);
    process.exit(1);
  }

  // Rename main file to .cjs for Node resolution with "type": "module"
  try {
    await rename("dist/cjs/index.js", "dist/cjs/index.cjs");
  } catch (e) {
    // no-op if already correct
  }
}

await build();