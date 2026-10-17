import { Component, ElementRef, computed, effect, inject, signal, viewChild } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router } from '@angular/router';
import { map } from 'rxjs';

import { Provider } from '../core/api';
import { AuthService } from '../core/auth';
import { ConfigService } from '../core/config';
import { describe, describeError } from '../core/errors';
import { GoogleSignIn } from '../core/google';
import { Passkeys } from '../core/passkeys';
import { supported as webauthnSupported } from '../core/webauthn';

@Component({
  selector: 'app-login',
  templateUrl: './login.html',
  styleUrl: './login.css',
})
export class Login {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly google = inject(GoogleSignIn);
  private readonly passkeys = inject(Passkeys);

  protected readonly config = inject(ConfigService).config;
  protected readonly webauthn = webauthnSupported();
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly googleFailed = signal(false);

  private readonly googleButton = viewChild<ElementRef<HTMLElement>>('googleButton');

  private readonly queryError = toSignal(
    inject(ActivatedRoute).queryParamMap.pipe(map((q) => q.get('error'))),
  );

  protected readonly message = computed(
    () => this.error() ?? (this.queryError() ? describe(this.queryError()) : null),
  );

  constructor() {
    effect(() => {
      const el = this.googleButton()?.nativeElement;
      const clientId = this.config()?.google_client_id;
      if (el && clientId) {
        this.google
          .render(
            el,
            clientId,
            'signin_with',
            (credential) => void this.signIn('google', credential),
          )
          .catch(() => this.googleFailed.set(true));
      }
    });
  }

  protected async withPasskey(): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    try {
      await this.signIn('passkeys', await this.passkeys.login());
    } catch (err) {
      this.error.set(describeError(err));
    } finally {
      this.busy.set(false);
    }
  }

  private async signIn(provider: Provider, credential: string): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    try {
      await this.auth.signIn(provider, credential);
      await this.router.navigateByUrl('/account');
    } catch (err) {
      this.error.set(describeError(err));
    } finally {
      this.busy.set(false);
    }
  }
}
