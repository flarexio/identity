import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { catchError, of } from 'rxjs';

import { API, FrontendConfig } from './api';

// Which sign-in methods the service has configured.
@Injectable({ providedIn: 'root' })
export class ConfigService {
  readonly config = toSignal(
    inject(HttpClient)
      .get<FrontendConfig>(`${API}/config`)
      .pipe(catchError(() => of<FrontendConfig>({ line: false, passkeys: false }))),
  );
}
