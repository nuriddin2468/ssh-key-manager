// The few WebExtension APIs the extension uses, typed for both Chrome
// (`chrome`) and Firefox (`browser`). Both return promises in Manifest V3.

declare namespace WebExt {
  interface MessageSender {
    id?: string;
    /** The frame's URL. */
    url?: string;
    /** The frame's origin, `'null'` if opaque (absent in older Firefox). */
    origin?: string;
    tab?: { id?: number };
    frameId?: number;
  }

  /** A browser setting under `privacy` (Chrome's `ChromeSetting`). */
  interface BrowserSetting {
    get(details: object): Promise<{
      value: unknown;
      levelOfControl:
        | 'not_controllable'
        | 'controlled_by_other_extensions'
        | 'controllable_by_this_extension'
        | 'controlled_by_this_extension';
    }>;
    set(details: { value: unknown }): Promise<unknown>;
    clear(details: object): Promise<unknown>;
  }

  interface Permissions {
    permissions?: string[];
  }

  interface StorageArea {
    get(keys?: string | string[] | null): Promise<Record<string, unknown>>;
    set(items: Record<string, unknown>): Promise<void>;
    remove(keys: string | string[]): Promise<void>;
  }

  interface Api {
    runtime: {
      id: string;
      sendNativeMessage(application: string, message: object): Promise<unknown>;
      sendMessage(message: unknown): Promise<unknown>;
      getURL(path: string): string;
      onMessage: {
        addListener(
          listener: (
            message: unknown,
            sender: MessageSender,
            sendResponse: (response?: unknown) => void,
          ) => boolean | undefined,
        ): void;
      };
    };
    storage: { session: StorageArea; local: StorageArea };
    permissions: {
      contains(permissions: Permissions): Promise<boolean>;
      request(permissions: Permissions): Promise<boolean>;
      onAdded: { addListener(listener: (permissions: Permissions) => void): void };
    };
    /** Only with the optional `privacy` permission. */
    privacy?: {
      services: {
        passwordSavingEnabled: BrowserSetting;
        /** Chromium only. */
        autofillAddressEnabled?: BrowserSetting;
      };
    };
    tabs: {
      create(properties: { url: string }): Promise<unknown>;
      /** A tab's `url` is there only with `activeTab` (the popup's own tab) or the `tabs` permission. */
      query(query: {
        active?: boolean;
        currentWindow?: boolean;
      }): Promise<{ id?: number; url?: string }[]>;
      sendMessage(
        tabId: number,
        message: unknown,
        options?: { frameId?: number },
      ): Promise<unknown>;
      onRemoved: { addListener(listener: (tabId: number) => void): void };
    };
  }
}

declare const chrome: WebExt.Api;
