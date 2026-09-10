import { requestUrl } from "obsidian";
import type { CloudSyncConfig, Entity } from "./baseTypes";
import { FakeFs } from "./fsAll";

export interface VaultChangeItem {
  rev: number;
  key: string;
  action: "put" | "delete" | "cursor";
  mtime: number;
  size?: number;
  cursor?: { line: number; ch: number };
}

export interface VaultChangesResponse {
  ok: boolean;
  revision: number;
  fullScanNeeded: boolean;
  changes: VaultChangeItem[];
}

export interface DeviceInfo {
  deviceId: string;
  deviceName: string;
  platform: "desktop" | "mobile" | "unknown";
  lastActive: number;
  lastBackup?: number;
  fileCount?: number;
}

export class FakeFsWorker extends FakeFs {
  kind = "cloudsync";
  config: CloudSyncConfig;
  vaultName: string;
  latestRevision?: number;

  constructor(config: CloudSyncConfig, vaultName: string) {
    super();
    this.config = config;
    this.vaultName = config.vaultId || vaultName;
  }

  private get baseUrl(): string {
    return (this.config.serverUrl || "").replace(/\/+$/, "");
  }

  private get headers(): Record<string, string> {
    const h: Record<string, string> = {};
    if (this.config.token) {
      h["Authorization"] = `Bearer ${this.config.token}`;
    }
    return h;
  }

  async walk(): Promise<Entity[]> {
    if (!this.baseUrl) {
      throw new Error("CloudSync server URL is not configured.");
    }
    const url = `${this.baseUrl}/api/sync/walk?vault=${encodeURIComponent(
      this.vaultName
    )}`;
    const res = await requestUrl({
      url,
      method: "GET",
      headers: this.headers,
    });

    if (res.status !== 200) {
      throw new Error(`CloudSync walk failed (${res.status}): ${res.text}`);
    }

    const json = res.json;
    if (json.revision !== undefined) {
      this.latestRevision = json.revision;
    }
    return (json.files || []) as Entity[];
  }

  async walkPartial(): Promise<Entity[]> {
    return this.walk();
  }

  async stat(key: string): Promise<Entity> {
    const url = `${this.baseUrl}/api/sync/file?vault=${encodeURIComponent(
      this.vaultName
    )}&key=${encodeURIComponent(key)}`;
    const res = await requestUrl({
      url,
      method: "HEAD",
      headers: this.headers,
      throw: false,
    });

    if (res.status === 404) {
      throw new Error(`File not found: ${key}`);
    }
    if (res.status !== 200) {
      throw new Error(`CloudSync stat failed (${res.status})`);
    }

    const mtime = Number.parseInt(res.headers["x-mtime"] || "0", 10);
    const size = Number.parseInt(res.headers["content-length"] || "0", 10);

    return {
      key,
      keyRaw: key,
      size,
      sizeRaw: size,
      mtimeCli: mtime > 0 ? mtime : undefined,
      mtimeSvr: mtime > 0 ? mtime : undefined,
      etag: res.headers["etag"],
    };
  }

  async mkdir(
    key: string,
    mtime?: number,
    ctime?: number
  ): Promise<Entity> {
    const normKey = key.endsWith("/") ? key : `${key}/`;
    const url = `${this.baseUrl}/api/sync/file?vault=${encodeURIComponent(
      this.vaultName
    )}&key=${encodeURIComponent(normKey)}`;

    const res = await requestUrl({
      url,
      method: "PUT",
      headers: {
        ...this.headers,
        "x-mtime": `${mtime ?? Date.now()}`,
        "x-ctime": `${ctime ?? Date.now()}`,
        "content-type": "application/x-directory",
      },
      body: new ArrayBuffer(0),
    });

    if (res.status !== 200 && res.status !== 201) {
      throw new Error(`CloudSync mkdir failed (${res.status}): ${res.text}`);
    }

    return {
      key: normKey,
      keyRaw: normKey,
      size: 0,
      sizeRaw: 0,
      mtimeCli: mtime,
      ctimeCli: ctime,
    };
  }

  async writeFile(
    key: string,
    content: ArrayBuffer,
    mtime: number,
    ctime: number,
    cursor?: { line: number; ch: number }
  ): Promise<Entity> {
    const url = `${this.baseUrl}/api/sync/file?vault=${encodeURIComponent(
      this.vaultName
    )}&key=${encodeURIComponent(key)}`;

    const headers: Record<string, string> = {
      ...this.headers,
      "x-mtime": `${mtime}`,
      "x-ctime": `${ctime}`,
      "content-type": "application/octet-stream",
    };

    if (cursor) {
      headers["x-cursor-line"] = `${cursor.line}`;
      headers["x-cursor-ch"] = `${cursor.ch}`;
    }

    const res = await requestUrl({
      url,
      method: "PUT",
      headers,
      body: content,
    });

    if (res.status !== 200 && res.status !== 201) {
      throw new Error(`CloudSync writeFile failed (${res.status}): ${res.text}`);
    }

    const json = res.json;
    if (json?.revision !== undefined) {
      this.latestRevision = json.revision;
    }

    return {
      key,
      keyRaw: key,
      size: content.byteLength,
      sizeRaw: content.byteLength,
      mtimeCli: mtime,
      ctimeCli: ctime,
      etag: res.headers["etag"],
    };
  }

  async readFile(key: string): Promise<ArrayBuffer> {
    const url = `${this.baseUrl}/api/sync/file?vault=${encodeURIComponent(
      this.vaultName
    )}&key=${encodeURIComponent(key)}`;

    const res = await requestUrl({
      url,
      method: "GET",
      headers: this.headers,
    });

    if (res.status !== 200) {
      throw new Error(`CloudSync readFile failed (${res.status}): ${res.text}`);
    }

    return res.arrayBuffer;
  }

  async rename(key1: string, key2: string): Promise<void> {
    const url = `${this.baseUrl}/api/sync/rename?vault=${encodeURIComponent(
      this.vaultName
    )}`;

    const res = await requestUrl({
      url,
      method: "POST",
      headers: {
        ...this.headers,
        "content-type": "application/json",
      },
      body: JSON.stringify({ from: key1, to: key2 }),
    });

    if (res.status !== 200) {
      throw new Error(`CloudSync rename failed (${res.status}): ${res.text}`);
    }

    if (res.json?.revision !== undefined) {
      this.latestRevision = res.json.revision;
    }
  }

  async rm(key: string): Promise<void> {
    const url = `${this.baseUrl}/api/sync/file?vault=${encodeURIComponent(
      this.vaultName
    )}&key=${encodeURIComponent(key)}`;

    const res = await requestUrl({
      url,
      method: "DELETE",
      headers: this.headers,
      throw: false,
    });

    if (res.status !== 200 && res.status !== 404) {
      throw new Error(`CloudSync rm failed (${res.status}): ${res.text}`);
    }

    if (res.json?.revision !== undefined) {
      this.latestRevision = res.json.revision;
    }
  }

  async getChanges(sinceRev: number): Promise<VaultChangesResponse> {
    if (!this.baseUrl || !this.config.token) {
      return { ok: false, revision: 0, fullScanNeeded: false, changes: [] };
    }
    const url = `${this.baseUrl}/api/sync/changes?vault=${encodeURIComponent(
      this.vaultName
    )}&since=${sinceRev}`;

    const res = await requestUrl({
      url,
      method: "GET",
      headers: this.headers,
      throw: false,
    });

    if (res.status !== 200) {
      throw new Error(`CloudSync getChanges failed (${res.status}): ${res.text}`);
    }

    const data = res.json as VaultChangesResponse;
    if (data.revision !== undefined) {
      this.latestRevision = data.revision;
    }
    return data;
  }

  async updateCursor(
    key: string,
    cursor: { line: number; ch: number }
  ): Promise<void> {
    if (!this.baseUrl || !this.config.token) return;
    const url = `${this.baseUrl}/api/sync/cursor?vault=${encodeURIComponent(
      this.vaultName
    )}&key=${encodeURIComponent(key)}`;

    const res = await requestUrl({
      url,
      method: "PUT",
      headers: {
        ...this.headers,
        "x-cursor-line": `${cursor.line}`,
        "x-cursor-ch": `${cursor.ch}`,
      },
      throw: false,
    });

    if (res.json?.revision !== undefined) {
      this.latestRevision = res.json.revision;
    }
  }

  async checkConnect(callbackFunc?: any): Promise<boolean> {
    try {
      if (!this.baseUrl) {
        throw new Error("Server URL not configured");
      }
      if (!this.config.token) {
        throw new Error("Not logged in");
      }
      const res = await requestUrl({
        url: `${this.baseUrl}/api/user/me`,
        method: "GET",
        headers: this.headers,
      });
      return res.status === 200;
    } catch (err) {
      callbackFunc?.(err);
      return false;
    }
  }

  async getUserDisplayName(): Promise<string> {
    return this.config.username || this.config.email || "CloudSync User";
  }

  async revokeAuth(): Promise<any> {
    this.config.token = "";
    this.config.userId = "";
    this.config.username = "";
    this.config.email = "";
  }

  async getDevices(): Promise<DeviceInfo[]> {
    if (!this.baseUrl || !this.config.token) return [];
    const url = `${this.baseUrl}/api/sync/devices?vault=${encodeURIComponent(
      this.vaultName
    )}`;

    const res = await requestUrl({
      url,
      method: "GET",
      headers: this.headers,
      throw: false,
    });

    if (res.status === 200 && res.json?.devices) {
      return res.json.devices;
    }
    return [];
  }

  async registerDevice(
    device: Partial<DeviceInfo> & { deviceId: string }
  ): Promise<void> {
    if (!this.baseUrl || !this.config.token) return;
    const url = `${this.baseUrl}/api/sync/devices?vault=${encodeURIComponent(
      this.vaultName
    )}`;

    await requestUrl({
      url,
      method: "PUT",
      headers: {
        ...this.headers,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(device),
      throw: false,
    });
  }

  async deleteDevice(deviceId: string): Promise<void> {
    if (!this.baseUrl || !this.config.token) return;
    const url = `${this.baseUrl}/api/sync/devices/${encodeURIComponent(
      deviceId
    )}?vault=${encodeURIComponent(this.vaultName)}`;

    await requestUrl({
      url,
      method: "DELETE",
      headers: this.headers,
      throw: false,
    });
  }

  allowEmptyFile(): boolean {
    return true;
  }
}
