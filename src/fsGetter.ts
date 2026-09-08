import type { RemotelySavePluginSettings } from "./baseTypes";
import type { FakeFs } from "./fsAll";

export function getClient(
  settings: RemotelySavePluginSettings,
  vaultName: string,
  saveUpdatedConfigFunc?: () => Promise<any>
): FakeFs {
  throw new Error(`cannot init client for serviceType=${settings.serviceType}`);
}
