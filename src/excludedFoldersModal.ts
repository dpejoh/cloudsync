import { App, Modal, Notice, Setting } from "obsidian";
import type CloudSyncPlugin from "./main";

export class ExcludedFoldersModal extends Modal {
  plugin: CloudSyncPlugin;
  private newFolderPath = "";

  constructor(app: App, plugin: CloudSyncPlugin) {
    super(app);
    this.plugin = plugin;
  }

  onOpen() {
    this.render();
  }

  onClose() {
    this.contentEl.empty();
  }

  private render() {
    const { contentEl } = this;
    contentEl.empty();

    contentEl.createEl("h2", {
      text: "Excluded folders",
      cls: "modal-title",
    });

    contentEl.createEl("p", {
      cls: "u-muted",
      text: "Files and folders listed below will be completely ignored by CloudSync and will not sync across devices.",
    });

    const listContainer = contentEl.createDiv({
      cls: "cloudsync-excluded-list-container",
    });

    const ignored = this.plugin.settings.ignorePaths || [];
    if (ignored.length === 0) {
      listContainer.createEl("p", {
        cls: "u-muted",
        text: "No folders are currently excluded.",
      });
    } else {
      for (let i = 0; i < ignored.length; i++) {
        const folder = ignored[i];
        const row = listContainer.createDiv({ cls: "cloudsync-share-user-row" });
        row.createSpan({ text: folder, cls: "cloudsync-share-username" });
        const removeBtn = row.createEl("button", {
          cls: "mod-destructive",
          text: "Remove",
        });
        removeBtn.onclick = async () => {
          this.plugin.settings.ignorePaths = (
            this.plugin.settings.ignorePaths || []
          ).filter((_, idx) => idx !== i);
          await this.plugin.saveSettings();
          this.render();
        };
      }
    }

    new Setting(contentEl)
      .setName("Add excluded folder")
      .setDesc("Folder path relative to vault root (e.g. Templates, Archive, .trash)")
      .addText((text) => {
        text
          .setPlaceholder("e.g. Templates")
          .setValue(this.newFolderPath)
          .onChange((val) => {
            this.newFolderPath = val;
          });
        text.inputEl.addEventListener("keydown", async (e) => {
          if (e.key === "Enter") await this.addFolder();
        });
      })
      .addButton((btn) => {
        btn
          .setButtonText("Add")
          .setCta()
          .onClick(async () => {
            await this.addFolder();
          });
      });

    const footer = contentEl.createDiv({ cls: "modal-button-container" });
    footer.createEl("button", { text: "Done" }, (btn) => {
      btn.onclick = () => this.close();
    });
  }

  private async addFolder() {
    const folder = this.newFolderPath.trim().replace(/^\/+|\/+$/g, "");
    if (!folder) return;

    const current = this.plugin.settings.ignorePaths || [];
    if (!current.includes(folder)) {
      current.push(folder);
      this.plugin.settings.ignorePaths = current;
      await this.plugin.saveSettings();
      new Notice(`Added "${folder}" to excluded folders.`);
    }
    this.newFolderPath = "";
    this.render();
  }
}
