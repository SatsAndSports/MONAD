// Fresh disposable databases per invocation; retained for inspection on exit.
import {mkdtemp, writeFile, open} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join, resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {spawn} from "node:child_process";
import {reserveTcpPort} from "./port-reservations.mjs";
const root = fileURLToPath(new URL("../../", import.meta.url));
export async function startDemo() {
  const directory = await mkdtemp(join(tmpdir(), "monad-mint-ui-"));
  const apiReservation = await reserveTcpPort();
  const apiPort = apiReservation.port;
  const config = join(directory, "demo.json");
  try {
    await writeFile(config, JSON.stringify({test_mints: ["demo-mint", "second-mint"].map(name => ({
      name, listen: "127.0.0.1:0", db_path: join(directory, `${name}.db`),
      units: {sat: {input_fee_ppk: 100}, msat: {input_fee_ppk: 200}},
    })), management: {listen: `127.0.0.1:${apiPort}`, test_mint_socket: join(directory, "mints.sock")}}));
  } catch (error) {
    await apiReservation.release();
    throw error;
  }
  const children = [];
  let stopping;
  async function launch(binary, args, reservation) {
    let child, log;
    try {
      log = await open(join(directory, `${binary}.log`), "a");
      if (stopping) throw Error("Demo is stopping");
      if (reservation) await reservation.release();
      if (stopping) throw Error("Demo is stopping");
      child = spawn(resolve(root, "target/debug", binary), args, {stdio: ["ignore", log.fd, log.fd]});
    } catch (error) {
      if (reservation) await reservation.release();
      await log?.close();
      throw error;
    }
    const done = new Promise(resolve => {child.once("exit", resolve); child.once("error", resolve);});
    children.push({child, done});
    await log.close();
    return {child, done};
  }
  const stopChild = async ({child, done}) => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    child.kill("SIGINT");
    if (await Promise.race([done.then(() => true), new Promise(resolve => setTimeout(() => resolve(false), 8000))])) return;
    child.kill("SIGKILL");
    await Promise.race([done, new Promise(resolve => setTimeout(resolve, 2000))]);
  };
  const emergency = () => {for (const {child} of children) if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");};
  const stop = () => stopping ??= (async () => {
    await apiReservation.release();
    process.off("exit", emergency);
    process.off("SIGINT", interrupted);
    process.off("SIGTERM", interrupted);
    for (const entry of [...children].reverse()) await stopChild(entry);
  })();
  const interrupted = () => {stop().finally(() => process.exit(0));};
  process.once("exit", emergency);
  process.once("SIGINT", interrupted);
  process.once("SIGTERM", interrupted);
  try {
    const mint = await launch("monad-test-mint", ["run", "--config", config]);
    await launch("monad-management", ["--config", config], apiReservation);
    const url = `http://127.0.0.1:${apiPort}`;
    for (let attempt = 0; attempt < 200; attempt++) {
      try {
        const state = await (await fetch(`${url}/v1/snapshot`)).json();
        if (state.processes["test-mints"]?.online) return {url, directory, stop, stopMint: () => stopChild(mint)};
      } catch {}
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error(`Demo startup timed out. Inspect ${directory}`);
  } catch (error) {await stop(); throw error;}
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const demo = await startDemo();
  console.log(`Mint UI: ${demo.url}/mints\nDisposable data and logs: ${demo.directory}\nPress Ctrl-C to stop.`);
}
