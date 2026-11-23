import { log } from "./logger.js";
import { createA2aServer, startupConfiguration } from "./server.js";

const port = Number(process.env.PORT ?? 3000);
log.info({ config: startupConfiguration() }, "[startup] configuration");
const serverResult = createA2aServer();

if (serverResult.isErr()) {
  log.error(
    serverResult.error,
    "[Forge Remote/FIT] server configuration failed",
  );
  process.exitCode = 1;
} else {
  const server = serverResult.value.listen(port, () => {
    const address = server.address();
    const listeningPort =
      address && typeof address !== "string" ? address.port : port;
    log.info({ port: listeningPort }, "[HTTP] server listening");
  });
}
