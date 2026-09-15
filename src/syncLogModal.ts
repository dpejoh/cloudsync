import { App, Modal, Notice, Setting } from "obsidian";
import type CloudSyncPlugin from "./main";

export interface SyncLogEntry {
  id: string;
  timestamp: number;
  type: "info" | "success" | "error" | "skipped" | "conflict";
  message: string;
  file?: string;
}

export class SyncLogModal extends Modal {
  plugin: CloudSyncPlugin;
  private filterType: "all" | "errors" | "skipped" | "merge" = "all";
  private searchQuery = "";
  private listEl!: HTMLElement;

  constructor(app: App, plugin: CloudSyncPlugin) {
    super(app);
    this.plugin = plugin;
  }

  onOpen() {
    this.modalEl.addClass("log-modal", "mod-lg");
    this.render();
  }

  onClose() {
    this.contentEl.empty();
  }

  private render() {
    const { contentEl } = this;
    contentEl.empty();

    contentEl.createEl("h2", {
      text: "Sync Activity Log",
      cls: "modal-title",
    });

    const controlsContainer = contentEl.createDiv({
      cls: "log-controls",
    });

    const drop = controlsContainer.createEl("select", { cls: "dropdown" });
    drop.createEl("option", { value: "all", text: "All events" });
    drop.createEl("option", { value: "errors", text: "Errors only" });
    drop.createEl("option", { value: "skipped", text: "Skipped only" });
    drop.createEl("option", { value: "merge", text: "Merge conflicts" });
    drop.value = this.filterType;
    drop.onchange = (e: any) => {
      this.filterType = e.target.value;
      this.renderList();
    };

    const searchInput = controlsContainer.createEl("input", {
      type: "search",
      cls: "log-search-input",
      value: this.searchQuery,
    });
    searchInput.placeholder = "Filter by message or file...";
    searchInput.oninput = (e: any) => {
      this.searchQuery = e.target.value.toLowerCase();
      this.renderList();
    };

    const copyBtn = controlsContainer.createEl("button", {
      text: "Copy log",
    });
    copyBtn.onclick = async () => {
      const text = this.getFormattedLogText();
      await navigator.clipboard.writeText(text);
      new Notice("Sync log copied to clipboard.");
    };

    const clearBtn = controlsContainer.createEl("button", {
      text: "Clear",
    });
    clearBtn.onclick = () => {
      this.plugin.syncLogs = [];
      this.renderList();
    };

    this.listEl = contentEl.createDiv({ cls: "log-container" });
    this.renderList();
  }

  private renderList() {
    if (!this.listEl) return;
    this.listEl.empty();

    const filtered = (this.plugin.syncLogs || []).filter((entry) => {
      if (this.filterType === "errors" && entry.type !== "error") return false;
      if (this.filterType === "skipped" && entry.type !== "skipped") return false;
      if (this.filterType === "merge" && entry.type !== "conflict") return false;

      if (this.searchQuery) {
        const text = `${entry.message} ${entry.file || ""}`.toLowerCase();
        if (!text.includes(this.searchQuery)) return false;
      }
      return true;
    });

    if (filtered.length === 0) {
      this.listEl.createEl("p", {
        cls: "u-muted",
        text: "No events found.",
      });
      return;
    }

    for (const entry of filtered) {
      const row = this.listEl.createDiv({
        cls: `log-row log-${entry.type}`,
      });

      const timeStr = new Date(entry.timestamp).toLocaleTimeString();
      row.createSpan({ text: timeStr, cls: "log-time" });

      const badge = row.createSpan({
        text: entry.type.toUpperCase(),
        cls: `log-badge badge-${entry.type}`,
      });

      const msgSpan = row.createSpan({
        text: entry.message,
        cls: "log-message",
      });

      if (entry.file) {
        row.createSpan({
          text: entry.file,
          cls: "log-file",
        });
      }
    }
  }

  private getFormattedLogText(): string {
    const logs = this.plugin.syncLogs || [];
    if (logs.length === 0) return "No sync activity logged.";

    return logs
      .map((entry) => {
        const time = new Date(entry.timestamp).toISOString();
        const type = entry.type.toUpperCase().padEnd(8);
        return `[${time}] [${type}] ${entry.message}${entry.file ? ` (${entry.file})` : ""}`;
      })
      .join("\n");
  }
}
