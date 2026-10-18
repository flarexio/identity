import { DatePipe } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import {
  Component,
  ElementRef,
  computed,
  effect,
  inject,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { firstValueFrom, map } from 'rxjs';

import { API, Provider, SocialAccount, User } from '../core/api';
import { AuthService } from '../core/auth';
import { ConfigService } from '../core/config';
import { describe, describeError } from '../core/errors';
import { GoogleSignIn } from '../core/google';
import { Passkeys } from '../core/passkeys';
import { supported as webauthnSupported } from '../core/webauthn';

const LINE_AUTHORIZE = 'https://access.line.me/';

export const providerNames: Record<Provider, string> = {
  google: 'Google',
  line: 'LINE',
  passkeys: '通行金鑰',
};

@Component({
  selector: 'app-account',
  imports: [DatePipe, FormsModule],
  templateUrl: './account.html',
  styleUrl: './account.css',
})
export class Account {
  private readonly http = inject(HttpClient);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly google = inject(GoogleSignIn);
  private readonly passkeys = inject(Passkeys);

  protected readonly config = inject(ConfigService).config;
  protected readonly user = this.auth.user;
  protected readonly webauthn = webauthnSupported();
  protected readonly names = providerNames;

  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly confirmDelete = signal(false);
  protected readonly googleFailed = signal(false);
  protected deleteInput = '';

  private readonly googleButton = viewChild<ElementRef<HTMLElement>>('googleButton');

  protected readonly has = computed(() => {
    const accounts = this.user()?.accounts ?? [];
    return (p: Provider) => accounts.some((a) => a.social_provider === p);
  });

  protected readonly canLinkGoogle = computed(
    () => !!this.config()?.google_client_id && !this.has()('google'),
  );
  protected readonly canLinkLINE = computed(() => !!this.config()?.line && !this.has()('line'));
  protected readonly canLinkPasskey = computed(
    () => !!this.config()?.passkeys && this.webauthn && !this.has()('passkeys'),
  );

  constructor() {
    const query = toSignal(inject(ActivatedRoute).queryParamMap.pipe(map((q) => q)));

    effect(() => {
      const q = query();
      untracked(() => {
        if (q?.get('linked') === 'line') {
          this.notice.set('已綁定 LINE 帳號。');
          void this.reload();
        } else if (q?.get('error')) {
          this.error.set(describe(q.get('error')));
        }
      });
    });

    effect(() => {
      const el = this.googleButton()?.nativeElement;
      const clientId = this.config()?.google_client_id;
      if (el && clientId) {
        this.google
          .render(
            el,
            clientId,
            'continue_with',
            (credential) => void this.link('google', credential),
          )
          .catch(() => this.googleFailed.set(true));
      }
    });
  }

  private path(): string {
    return `${API}/users/${encodeURIComponent(this.user()!.username)}`;
  }

  private async run(action: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.notice.set(null);
    try {
      await action();
    } catch (err) {
      this.error.set(describeError(err));
    } finally {
      this.busy.set(false);
    }
  }

  private async reload(): Promise<void> {
    try {
      this.auth.updateUser(await firstValueFrom(this.http.get<User>(this.path())));
    } catch {
      // Keep what we have; the change shows on the next load.
    }
  }

  protected link(provider: Provider, credential: string): Promise<void> {
    return this.run(async () => {
      const user = await firstValueFrom(
        this.http.put<User>(`${this.path()}/socials`, { provider, credential }),
      );
      this.auth.updateUser(user);
      this.notice.set(`已綁定${providerNames[provider]}。`);
    });
  }

  protected linkLINE(): Promise<void> {
    return this.run(async () => {
      const url = await firstValueFrom(
        this.http.get(`/auth/line/link/${encodeURIComponent(this.user()!.username)}`, {
          responseType: 'text',
        }),
      );

      // Only ever navigate to LINE's own authorization page.
      if (!url.startsWith(LINE_AUTHORIZE)) {
        throw new Error('unexpected authorization URL');
      }

      window.location.assign(url);
    });
  }

  protected addPasskey(): Promise<void> {
    return this.run(async () => {
      const token = await this.passkeys.register(this.user()!.username);
      const user = await firstValueFrom(
        this.http.put<User>(`${this.path()}/socials`, { provider: 'passkeys', credential: token }),
      );
      this.auth.updateUser(user);
      this.notice.set('已新增通行金鑰。');
    });
  }

  protected unlink(account: SocialAccount): Promise<void> {
    const name = providerNames[account.social_provider] ?? account.social_provider;
    if (!confirm(`確定要解除綁定${name}嗎？`)) {
      return Promise.resolve();
    }

    return this.run(async () => {
      const user = await firstValueFrom(
        this.http.delete<User>(`${this.path()}/socials`, {
          body: { provider: account.social_provider, social_id: account.social_id },
        }),
      );
      this.auth.updateUser(user);
      this.notice.set(`已解除綁定${name}。`);
    });
  }

  protected deleteAccount(): Promise<void> {
    if (this.deleteInput !== this.user()?.username) {
      return Promise.resolve();
    }

    return this.run(async () => {
      await firstValueFrom(this.http.delete(this.path()));
      this.auth.clear();
      await this.router.navigateByUrl('/login');
    });
  }
}
