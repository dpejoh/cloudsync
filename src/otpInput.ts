export interface OtpInputOptions {
  length?: number;
  initialValue?: string;
  autoFocus?: boolean;
  onComplete?: (code: string) => void;
  onChange?: (code: string) => void;
}

export interface OtpInputHandle {
  containerEl: HTMLElement;
  getValue: () => string;
  setValue: (code: string) => void;
  focus: (index?: number) => void;
  clear: () => void;
  setDisabled: (disabled: boolean) => void;
}

export function createOtpInput(
  parentEl: HTMLElement,
  options: OtpInputOptions = {}
): OtpInputHandle {
  const length = options.length ?? 6;
  const container = parentEl.createDiv({ cls: "cloudsync-otp-squares-container" });
  const inputs: HTMLInputElement[] = [];

  for (let i = 0; i < length; i++) {
    const input = container.createEl("input", {
      type: "text",
      cls: "cloudsync-otp-square",
      attr: {
        maxlength: "1",
        inputmode: "numeric",
        pattern: "[0-9]*",
        autocomplete: i === 0 ? "one-time-code" : "off",
        "aria-label": `Digit ${i + 1}`,
      },
    });

    if (options.initialValue && options.initialValue[i]) {
      input.value = options.initialValue[i];
      input.addClass("is-filled");
    }

    inputs.push(input);

    input.addEventListener("focus", () => {
      input.select();
    });

    input.addEventListener("click", () => {
      input.select();
    });

    input.addEventListener("keydown", (e: KeyboardEvent) => {
      if (e.key === "Backspace") {
        e.preventDefault();
        if (input.value) {
          input.value = "";
          input.removeClass("is-filled");
          notifyChange();
        } else if (i > 0) {
          inputs[i - 1].value = "";
          inputs[i - 1].removeClass("is-filled");
          inputs[i - 1].focus();
          notifyChange();
        }
        return;
      }

      if (e.key === "ArrowLeft" && i > 0) {
        e.preventDefault();
        inputs[i - 1].focus();
        inputs[i - 1].select();
        return;
      }

      if (e.key === "ArrowRight" && i < length - 1) {
        e.preventDefault();
        inputs[i + 1].focus();
        inputs[i + 1].select();
        return;
      }

      if (e.key === "Enter") {
        const full = getFullValue();
        if (full.length === length) {
          e.preventDefault();
          options.onComplete?.(full);
        }
        return;
      }

      // Ignore non-digit printable keys
      if (e.key.length === 1 && !/\d/.test(e.key) && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
      }
    });

    input.addEventListener("input", (e: Event) => {
      const target = e.target as HTMLInputElement;
      const rawVal = target.value.replace(/\D/g, "");

      if (rawVal.length === 0) {
        target.value = "";
        target.removeClass("is-filled");
        notifyChange();
        return;
      }

      if (rawVal.length === 1) {
        target.value = rawVal;
        target.addClass("is-filled");
        if (i < length - 1) {
          inputs[i + 1].focus();
          inputs[i + 1].select();
        }
        notifyChange();
        return;
      }

      // Multi-character input (mobile autofill or fast typing)
      fillFromIndex(i, rawVal);
    });

    input.addEventListener("paste", (e: ClipboardEvent) => {
      e.preventDefault();
      const text = e.clipboardData?.getData("text") || "";
      const digits = text.replace(/\D/g, "");
      if (digits.length > 0) {
        fillFromIndex(0, digits);
      }
    });
  }

  function fillFromIndex(startIndex: number, digits: string) {
    let cur = startIndex;
    for (let d = 0; d < digits.length && cur < length; d++) {
      inputs[cur].value = digits[d];
      inputs[cur].addClass("is-filled");
      cur++;
    }
    const nextToFocus = Math.min(cur, length - 1);
    inputs[nextToFocus].focus();
    inputs[nextToFocus].select();
    notifyChange();
  }

  function getFullValue(): string {
    return inputs.map((inp) => inp.value).join("");
  }

  function notifyChange() {
    const val = getFullValue();
    options.onChange?.(val);
    if (val.length === length) {
      options.onComplete?.(val);
    }
  }

  if (options.autoFocus !== false) {
    setTimeout(() => {
      inputs[0]?.focus();
      inputs[0]?.select();
    }, 60);
  }

  return {
    containerEl: container,
    getValue: () => getFullValue(),
    setValue: (code: string) => {
      fillFromIndex(0, code.replace(/\D/g, "").slice(0, length));
    },
    focus: (index = 0) => {
      const idx = Math.max(0, Math.min(index, length - 1));
      inputs[idx]?.focus();
      inputs[idx]?.select();
    },
    clear: () => {
      for (const inp of inputs) {
        inp.value = "";
        inp.removeClass("is-filled");
      }
      notifyChange();
      inputs[0]?.focus();
    },
    setDisabled: (disabled: boolean) => {
      for (const inp of inputs) {
        inp.disabled = disabled;
      }
    },
  };
}
