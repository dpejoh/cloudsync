import { type Extension, type Range, StateEffect, StateField } from "@codemirror/state";
import { Decoration, type DecorationSet, EditorView, WidgetType } from "@codemirror/view";

const PALETTE = [
  "#2563EB", // Blue
  "#059669", // Emerald
  "#D97706", // Amber
  "#DC2626", // Red
  "#7C3AED", // Violet
  "#DB2777", // Pink
  "#0D9488", // Teal
  "#EA580C", // Orange
];

export function getDeviceColor(deviceId: string): string {
  let hash = 0;
  for (let i = 0; i < deviceId.length; i++) {
    hash = (hash << 5) - hash + deviceId.charCodeAt(i);
    hash |= 0;
  }
  const idx = Math.abs(hash) % PALETTE.length;
  return PALETTE[idx];
}

export interface RemoteCursorPresence {
  deviceId: string;
  deviceName: string;
  color: string;
  path: string;
  line: number;
  ch: number;
  updatedAt: number;
  firstSeenAt: number;
}

class RemoteCursorWidget extends WidgetType {
  constructor(
    readonly deviceId: string,
    readonly deviceName: string,
    readonly color: string,
    readonly isFirstArrival: boolean
  ) {
    super();
  }

  eq(other: WidgetType): boolean {
    return (
      other instanceof RemoteCursorWidget &&
      other.deviceId === this.deviceId &&
      other.deviceName === this.deviceName &&
      other.color === this.color &&
      other.isFirstArrival === this.isFirstArrival
    );
  }

  toDOM(): HTMLElement {
    const wrap = document.createElement("span");
    wrap.className = "cloudsync-remote-cursor-wrap";
    wrap.setAttribute("title", this.deviceName);

    const flag = document.createElement("span");
    flag.className = "cloudsync-remote-cursor-flag";
    if (this.isFirstArrival) {
      flag.classList.add("cloudsync-initial-arrival");
    }
    flag.textContent = this.deviceName;
    flag.style.backgroundColor = this.color;

    const bar = document.createElement("span");
    bar.className = "cloudsync-remote-cursor-bar";
    bar.style.backgroundColor = this.color;

    wrap.appendChild(flag);
    wrap.appendChild(bar);

    const triggerReveal = (e: Event) => {
      e.stopPropagation();
      wrap.classList.add("cloudsync-flag-revealed");
      const existingTimer = (wrap as any)._revealTimer;
      if (existingTimer) {
        window.clearTimeout(existingTimer);
      }
      (wrap as any)._revealTimer = window.setTimeout(() => {
        wrap.classList.remove("cloudsync-flag-revealed");
        delete (wrap as any)._revealTimer;
      }, 3000);
    };

    wrap.addEventListener("pointerdown", triggerReveal);
    wrap.addEventListener("click", triggerReveal);

    return wrap;
  }

  destroy(dom: HTMLElement): void {
    const timer = (dom as any)._revealTimer;
    if (timer) {
      window.clearTimeout(timer);
    }
  }

  ignoreEvent(): boolean {
    return true;
  }
}

export const setRemotePresencesEffect =
  StateEffect.define<RemoteCursorPresence[]>();

export const remoteCursorField = StateField.define<DecorationSet>({
  create() {
    return Decoration.none;
  },
  update(decorations, tr) {
    decorations = decorations.map(tr.changes);

    for (const e of tr.effects) {
      if (e.is(setRemotePresencesEffect)) {
        if (!e.value || e.value.length === 0) {
          decorations = Decoration.none;
          break;
        }

        const now = Date.now();
        const widgets: Range<Decoration>[] = [];
        for (const p of e.value) {
          const lineNum = Math.min(Math.max(1, p.line + 1), tr.state.doc.lines);
          const line = tr.state.doc.line(lineNum);
          const pos = line.from + Math.min(Math.max(0, p.ch), line.length);
          const isFirstArrival = now - p.firstSeenAt < 3200;

          widgets.push(
            Decoration.widget({
              widget: new RemoteCursorWidget(
                p.deviceId,
                p.deviceName,
                p.color,
                isFirstArrival
              ),
              side: 1,
            }).range(pos)
          );
        }

        widgets.sort((a, b) => a.from - b.from);
        decorations = Decoration.set(widgets, true);
      }
    }

    return decorations;
  },
  provide: (f) => EditorView.decorations.from(f),
});

export function createCursorListener(
  onCursorMove: (cursor: { line: number; ch: number }) => void
): Extension {
  return EditorView.updateListener.of((update) => {
    if (!update.selectionSet && !update.docChanged) return;

    const head = update.state.selection.main.head;
    const line = update.state.doc.lineAt(head);
    const cursor = {
      line: line.number - 1,
      ch: head - line.from,
    };

    onCursorMove(cursor);
  });
}
