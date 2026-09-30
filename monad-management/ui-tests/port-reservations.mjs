import { createSocket } from "node:dgram";
import { createServer } from "node:net";

const HOST = "127.0.0.1";
const SHARED_PORT_ATTEMPTS = 128;

function validatePort(port) {
  if (!Number.isInteger(port) || port < 0 || port > 65535)
    throw Error("Demo ports must be integers from 0 to 65535");
}

async function bindTcp(port) {
  const server = createServer();
  await new Promise((resolve, reject) => {
    const failed = (error) => {
      server.off("listening", ready);
      reject(error);
    };
    const ready = () => {
      server.off("error", failed);
      resolve();
    };
    server.once("error", failed);
    server.once("listening", ready);
    server.listen({ host: HOST, port, exclusive: true });
  });
  return server;
}

async function bindUdp(port) {
  const socket = createSocket("udp4");
  try {
    await new Promise((resolve, reject) => {
      const failed = (error) => {
        socket.off("listening", ready);
        reject(error);
      };
      const ready = () => {
        socket.off("error", failed);
        resolve();
      };
      socket.once("error", failed);
      socket.once("listening", ready);
      socket.bind(port, HOST);
    });
    return socket;
  } catch (error) {
    try {
      socket.close();
    } catch {}
    throw error;
  }
}

export async function reserveTcpPort(requestedPort = 0) {
  validatePort(requestedPort);
  const server = await bindTcp(requestedPort);
  const port = server.address().port;
  let releasePromise;
  return {
    port,
    release: () =>
      (releasePromise ??= new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      )),
  };
}

export async function reserveRelayPort(requestedPort = 0) {
  validatePort(requestedPort);
  let lastError;
  const attempts = requestedPort === 0 ? SHARED_PORT_ATTEMPTS : 1;
  for (let attempt = 0; attempt < attempts; attempt++) {
    const tcp = await reserveTcpPort(requestedPort);
    try {
      const udp = await bindUdp(tcp.port);
      let releasePromise;
      return {
        port: tcp.port,
        release: () =>
          (releasePromise ??= Promise.all([
            tcp.release(),
            new Promise((resolve) => udp.close(resolve)),
          ]).then(() => undefined)),
      };
    } catch (error) {
      await tcp.release();
      lastError = error;
      if (requestedPort !== 0 || error.code !== "EADDRINUSE") throw error;
    }
  }
  const error = new Error(
    `Could not reserve a shared TCP/UDP demo port after ${SHARED_PORT_ATTEMPTS} attempts`,
  );
  error.code = "EADDRINUSE";
  error.cause = lastError;
  throw error;
}
