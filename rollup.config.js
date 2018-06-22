import builtins from "rollup-plugin-node-builtins";
import typescript from "rollup-plugin-typescript";

let pkg = require("./package.json");

let banner = [
    "/**",
    " *",
    " * 2key-ratchet",
    " * Copyright (c) 2016 Peculiar Ventures, Inc",
    " * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and",
    " * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems",
    " *",
    " */",
]

export default {
    input: "src/index.ts",
    plugins: [
        typescript({ typescript: require("typescript"), target: "es5", removeComments: true }),
        builtins(),
    ],
    external: ["protobufjs", "tslib", "pvtsutils", "tsprotobuf"],
    output: {
        banner: banner.join("\n"),
        globals: {
            protobufjs: "protobufjs",
            tslib: "tslib",
            "pvtsutils": "TSTool",
            "tsprotobuf": "TSProtobuf",
        },
        file: pkg.main,
        format: "umd",
        name: "DKeyRatchet",
    }
};