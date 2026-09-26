import type { RemotelySavePluginSettings } from "./baseTypes";
import type { FakeFs } from "./fsAll";
import { FakeFsWorker } from "./fsWorker";

export function getClient(
  settings: RemotelySavePluginSettings,
  vaultName: string,
): FakeFs {
  const cfg = {
    ...settings.cloudsync,
    deviceId: settings.deviceId,
    deviceName: settings.deviceName,
  };
  return new FakeFsWorker(cfg, vaultName);
}
