import typescript from "rollup-plugin-typescript";
import ts from "typescript";

let pkg = require("./package.json");

let banner = [
  "/**",
  " *",
  " * 2key-ratchet",
  " * Copyright (c) 2019 Peculiar Ventures, Inc",
  " * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and",
  " * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems",
  " *",
  " */",
]

const input = "src/index.ts";
const external = Object.keys(pkg.dependencies).concat(["events"]);

export default [
  {
    input,
    plugins: [
      typescript({ typescript: ts, target: "esnext", removeComments: true }),
    ],
    external,
    output: {
      banner: banner.join("\n"),
      file: pkg.main,
      format: "cjs",
    },
  },
  {
    input,
    plugins: [
      typescript({ typescript: ts, target: "esnext", removeComments: true }),
    ],
    external,
    output: {
      banner: banner.join("\n"),
      file: pkg.module,
      format: "es",
    },
  },
];