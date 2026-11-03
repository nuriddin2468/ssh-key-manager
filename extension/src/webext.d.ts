// The few WebExtension APIs the extension uses, typed for both Chrome
// (`chrome`) and Firefox (`browser`). Both return promises in Manifest V3.

declare namespace WebExt {
  interface MessageSender {
    id?: string;
    /** The frame's URL. */
    url?: string;
    /** The frame's origin (Chrome only). */
    origin?: string;
    tab?: { id?: number };
    frameId?: number;
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
    tabs: {
      create(properties: { url: string }): Promise<unknown>;
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
