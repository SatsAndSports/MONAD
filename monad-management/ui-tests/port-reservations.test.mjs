import { createSocket } from "node:dgram";
import { createServer } from "node:net";
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  reserveRelayPort,
  reserveTcpPort,
} from "./port-reservations.mjs";

const HOST = "127.0.0.1";

async function listenTcp(port) {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, HOST, resolve);
  });
  return server;
}

async function listenUdp(port) {
  const socket = createSocket("udp4");
  await new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(port, HOST, resolve);
  });
  return socket;
}

const closeTcp = (server) => new Promise((resolve) => server.close(resolve));
const closeUdp = (socket) => new Promise((resolve) => socket.close(resolve));

test("TCP reservations are held, exact, and idempotently released", async () => {
  const reservation = await reserveTcpPort();
  await assert.rejects(listenTcp(reservation.port), { code: "EADDRINUSE" });
  await assert.rejects(reserveTcpPort(reservation.port), {
    code: "EADDRINUSE",
  });
  await Promise.all([reservation.release(), reservation.release()]);

  const exact = await reserveTcpPort(reservation.port);
  assert.equal(exact.port, reservation.port);
  await exact.release();
  const reusable = await listenTcp(reservation.port);
  await closeTcp(reusable);
});

test("relay reservations hold the same TCP and UDP port", async () => {
  const reservation = await reserveRelayPort();
  await assert.rejects(listenTcp(reservation.port), { code: "EADDRINUSE" });
  await assert.rejects(listenUdp(reservation.port), { code: "EADDRINUSE" });
  await reservation.release();

  const tcp = await listenTcp(reservation.port);
  const udp = await listenUdp(reservation.port);
  await Promise.all([closeTcp(tcp), closeUdp(udp)]);
});

test("failed explicit relay reservation releases provisional TCP", async () => {
  const udp = await listenUdp(0);
  const port = udp.address().port;
  try {
    await assert.rejects(reserveRelayPort(port), { code: "EADDRINUSE" });
    const tcp = await listenTcp(port);
    await closeTcp(tcp);
  } finally {
    await closeUdp(udp);
  }
});

test("held reservations are distinct and invalid ports are rejected", async () => {
  for (const value of [-1, 65536, 1.5, NaN, "0"]) {
    await assert.rejects(reserveTcpPort(value), /integers from 0 to 65535/);
    await assert.rejects(reserveRelayPort(value), /integers from 0 to 65535/);
  }

  const reservations = await Promise.all([
    reserveTcpPort(),
    reserveTcpPort(),
    reserveRelayPort(),
    reserveRelayPort(),
  ]);
  try {
    assert.equal(new Set(reservations.map(({ port }) => port)).size, 4);
  } finally {
    await Promise.all(reservations.map(({ release }) => release()));
  }
});
