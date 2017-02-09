// import nodeResolve from "rollup-plugin-node-resolve";
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
    entry: "src/classes/index.ts",
    plugins: [
        typescript({ typescript: require("typescript"), target: "es5", removeComments: true }),
    ],
    banner: banner.join("\n"),
    external: ["protobufjs", "tslib", "pvtsutils", "tsprotobuf"],
    globals: {
        protobufjs: "protobufjs",
        tslib: "tslib",
        "pvtsutils": "TSTool",
        "tsprotobuf": "TSProtobuf",
    },
    targets: [
        {
            dest: pkg.main,
            format: "umd",
            moduleName: "DKeyRatchet"
        }
    ]
};