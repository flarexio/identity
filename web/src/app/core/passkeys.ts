import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { API } from './api';
import { creationOptions, requestOptions, toJSON } from './webauthn';

interface Options {
  publicKey: Record<string, unknown>;
}

// Passkey ceremonies. Each ends with a token from the Passkeys API, which
// the caller presents to identity to sign in or to link the passkey.
@Injectable({ providedIn: 'root' })
export class Passkeys {
  private readonly http = inject(HttpClient);

  async login(): Promise<string> {
    const opts = await firstValueFrom(
      this.http.post<Options>(`${API}/passkeys/login/initialize`, {}),
    );

    const cred = await navigator.credentials.get({ publicKey: requestOptions(opts.publicKey) });
    if (!(cred instanceof PublicKeyCredential)) {
      throw new DOMException('no credential', 'NotAllowedError');
    }

    return firstValueFrom(this.http.post<string>(`${API}/passkeys/login/finalize`, toJSON(cred)));
  }

  async register(username: string): Promise<string> {
    const opts = await firstValueFrom(
      this.http.post<Options>(
        `${API}/users/${encodeURIComponent(username)}/passkeys/register`,
        null,
      ),
    );

    const cred = await navigator.credentials.create({ publicKey: creationOptions(opts.publicKey) });
    if (!(cred instanceof PublicKeyCredential)) {
      throw new DOMException('no credential', 'NotAllowedError');
    }

    return firstValueFrom(this.http.post<string>(`${API}/passkeys/registration`, toJSON(cred)));
  }
}
