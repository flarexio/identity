import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, computed, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { API, Provider, SignInResponse, Token, User } from './api';

const RENEW_MARGIN_MS = 60_000;

// The access token is held in memory only, never in storage a script could
// read later. The HttpOnly session cookie the service sets at sign-in is
// what survives a reload; restore() trades it for a fresh access token.
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);

  private readonly state = signal<{ user: User; token: Token } | null>(null);
  private renewTimer?: ReturnType<typeof setTimeout>;
  private restoring?: Promise<boolean>;

  readonly user = computed(() => this.state()?.user ?? null);
  readonly signedIn = computed(() => this.state() !== null);

  token(): string | null {
    return this.state()?.token.token ?? null;
  }

  async signIn(provider: Provider, credential: string): Promise<User> {
    const resp = await firstValueFrom(
      this.http.patch<SignInResponse>(`${API}/signin`, { provider, credential }),
    );
    this.accept(resp);
    return resp.user;
  }

  // Restores the session from the cookie. Concurrent callers share one
  // request, so a burst of 401s does not become a burst of exchanges.
  restore(attempts = 1): Promise<boolean> {
    this.restoring ??= this.exchange(attempts).finally(() => (this.restoring = undefined));
    return this.restoring;
  }

  private async exchange(attempts: number): Promise<boolean> {
    for (let i = 0; i < attempts; i++) {
      try {
        const resp = await firstValueFrom(
          this.http.post<SignInResponse>(`${API}/session/token`, null),
        );
        this.accept(resp);
        return true;
      } catch (err) {
        // A brand-new account is written asynchronously; give it a moment.
        const retry = err instanceof HttpErrorResponse && err.status === 401 && i + 1 < attempts;
        if (!retry) {
          break;
        }
        await new Promise((r) => setTimeout(r, 400 * (i + 1)));
      }
    }

    this.clear();
    return false;
  }

  updateUser(user: User): void {
    const state = this.state();
    if (state) {
      this.state.set({ ...state, user });
    }
  }

  async signOut(): Promise<void> {
    this.clear();
    try {
      await firstValueFrom(this.http.delete(`${API}/session`));
    } catch {
      // The local state is gone either way.
    }
  }

  // Forget the session locally, e.g. after the account was deleted (the
  // service has already cleared the cookie).
  clear(): void {
    clearTimeout(this.renewTimer);
    this.state.set(null);
  }

  private accept(resp: SignInResponse): void {
    this.state.set({ user: resp.user, token: resp.token });

    clearTimeout(this.renewTimer);
    const delay = new Date(resp.token.expired_at).getTime() - Date.now() - RENEW_MARGIN_MS;
    this.renewTimer = setTimeout(() => void this.restore(), Math.max(delay, 5_000));
  }
}
