// tslint:disable: no-console

import { Crypto } from "@peculiar/webcrypto";
import * as DKeyRatchet from "..";
import { Client } from "./client";
import { Server } from "./server";

async function main() {
  const crypto = new Crypto();
  DKeyRatchet.setEngine("@peculiar/webcrypto", crypto);

  const server = await Server.create(1);
  server.on("listening", (address) => {
    console.log(`Server: ${address.address}:${address.port}`);
  });

  server.on("error", (e) => console.error("Server:", e));

  server.once("message", (text) => {
    console.log("Server <-", text);
    server.send("Hello! I'm Server. Who are you?");
    server.on("message", (text2) => {
      console.log("Server <-", text2);
    });
  });

  const client = await Client.create(2);
  client.on("listening", (address) => {
    console.log(`Client: ${address.address}:${address.port}`);
  });

  client.on("message", (text) => {
    console.log("Client <-", text);
    client.send("I'm your client");
  });

  client.on("connected", () => {
    console.log("Connected");
    client.send("hello!!!");
  });

  client.on("error", (e) => console.error("Client:", e));

  setTimeout(() => {
    client.connect();
  }, 1e3);
}

main()
  .catch((e) => console.error(e));
