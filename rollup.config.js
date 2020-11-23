import resolve from "@rollup/plugin-node-resolve";
import { getBabelOutputPlugin } from "@rollup/plugin-babel";
import commonjs from "@rollup/plugin-commonjs";
import nodePolyfills from "rollup-plugin-node-polyfills";
import typescript from "rollup-plugin-typescript2";
const pkg = require("./package.json");

const banner = [
  "/**",
  " * Copyright (c) 2016-2020, Peculiar Ventures, All rights reserved.",
  " */",
  "",
].join("\n");
const input = "src/index.ts";
const external = Object.keys(pkg.dependencies).concat(["events"]);

export default [
  {
    input,
    plugins: [
      typescript({
        check: true,
        clean: true,
        tsconfigOverride: {
          compilerOptions: {
            module: "ES2015",
            removeComments: true,
          }
        }
      }),
    ],
    external,
    output: [
      {
        banner,
        file: pkg.main,
        format: "cjs",
        name: "ratchet"
      },
      {
        banner,
        file: pkg.module,
        format: "es",
      },
    ],
  },
  {
    input,
    context: "this",
    plugins: [
      resolve({
        mainFields: ["esnext", "module", "main"],
        preferBuiltins: true,
      }),
      nodePolyfills(),
      commonjs(),
      typescript({
        check: true,
        clean: true,
        tsconfigOverride: {
          compilerOptions: {
            module: "es2015",
          }
        }
      }),
    ],
    output: [
      {
        banner,
        file: pkg.browser,
        format: "iife",
        plugins: [
          getBabelOutputPlugin({
            allowAllFormats: true,
            presets: [
              ["@babel/preset-env", {
                targets: {
                  chrome: "60"
                },
              }],
            ],
          }),
        ],
        name: "dKeyRatchet"
      }
    ]
  },
];
