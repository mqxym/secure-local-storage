// Build ESM + CJS bundles with Bun, targeting browsers.
const { rename, rm , cp} = await import("fs/promises");
import path from "path";

async function build() {
  // clean old build
  await rm("dist", { recursive: true }).catch(() => {});
  await rm(path.resolve(__dirname, 'examples', 'dist'), { recursive: true }).catch(() => {});

  // ESM
  let esm = await Bun.build({
    entrypoints: ["src/index.ts"],
    outdir: "dist/esm",
    target: "browser",
    format: "esm",
   minify: {
      whitespace: true,
      identifiers: false,
      syntax: true,
      keepNames: true,
    },
    sourcemap: "external",
        naming: {
    entry: "sls.browser.min.[ext]",
    chunk: "[name]-[hash].[ext]",
    asset: "[name].[ext]",
  },
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
    minify: {
      whitespace: true,
      identifiers: false,
      syntax: true,
      keepNames: true,
    },
    sourcemap: "external",
    naming: {
    entry: "sls.browser.min.[ext]",
    chunk: "[name]-[hash].[ext]",
    asset: "[name].[ext]",
  },
  });
  if (!cjs.success) {
    console.error("CJS build failed", cjs.logs);
    process.exit(1);
  }

  // Rename main file to .cjs for Node resolution with "type": "module"
  try {
    await rename("dist/cjs/sls.browser.min.js", "dist/cjs/sls.browser.min.cjs");
  } catch (e) {
    // no-op if already correct
  }
}

async function copyEsmDistToExamples() {
  const srcDir = path.resolve(__dirname, 'dist', 'esm');
  const destDir = path.resolve(__dirname, 'examples', 'dist');

  // The recursive: true option makes sure all subdirectories + files are copied
  await cp(srcDir, destDir, { recursive: true });
  console.log('Copied esm dist to examples/dist');
}


await build();
await copyEsmDistToExamples();