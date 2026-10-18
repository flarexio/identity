import { Injectable } from '@angular/core';

// The slice of Google Identity Services this app uses.
interface GoogleAccountsId {
  initialize(config: {
    client_id: string;
    callback: (resp: { credential: string }) => void;
    ux_mode?: 'popup';
    use_fedcm_for_button?: boolean;
  }): void;
  renderButton(parent: HTMLElement, options: Record<string, unknown>): void;
}

declare global {
  interface Window {
    google?: { accounts: { id: GoogleAccountsId } };
  }
}

const SCRIPT = 'https://accounts.google.com/gsi/client';

@Injectable({ providedIn: 'root' })
export class GoogleSignIn {
  private loading?: Promise<GoogleAccountsId>;

  private load(): Promise<GoogleAccountsId> {
    this.loading ??= new Promise((resolve, reject) => {
      if (window.google?.accounts?.id) {
        resolve(window.google.accounts.id);
        return;
      }

      const script = document.createElement('script');
      script.src = SCRIPT;
      script.async = true;
      script.onload = () =>
        window.google?.accounts?.id
          ? resolve(window.google.accounts.id)
          : reject(new Error('Google Identity Services did not load'));
      script.onerror = () => {
        this.loading = undefined;
        reject(new Error('Google Identity Services did not load'));
      };
      document.head.appendChild(script);
    });

    return this.loading;
  }

  // Renders Google's button into parent; onCredential receives the ID token.
  // GIS keeps one callback per page, so the last button rendered wins.
  async render(
    parent: HTMLElement,
    clientId: string,
    text: 'signin_with' | 'continue_with',
    onCredential: (credential: string) => void,
  ): Promise<void> {
    const gis = await this.load();

    gis.initialize({
      client_id: clientId,
      callback: (resp) => onCredential(resp.credential),
      ux_mode: 'popup',
      use_fedcm_for_button: true,
    });

    gis.renderButton(parent, {
      type: 'standard',
      theme: 'outline',
      size: 'large',
      shape: 'pill',
      text,
      width: 280,
      locale: 'zh-TW',
    });
  }
}
