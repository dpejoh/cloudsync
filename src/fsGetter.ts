import type { RemotelySavePluginSettings } from "./baseTypes";
import type { FakeFs } from "./fsAll";
import { FakeFsWorker } from "./fsWorker";

export function getClient(
  settings: RemotelySavePluginSettings,
  vaultName: string,
  saveUpdatedConfigFunc?: () => Promise<any>
): FakeFs {
  return new FakeFsWorker(settings.cloudsync, vaultName);
}
