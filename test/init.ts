import {Crypto} from "@peculiar/webcrypto";
import { setEngine } from "../src";

setEngine("@peculiar/webcrypto", new Crypto());
