import { HttpErrorResponse, HttpInterceptorFn, HttpRequest } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, from, switchMap, throwError } from 'rxjs';

import { API } from './api';
import { AuthService } from './auth';

// Only identity's own endpoints that need it get the bearer token. Absolute
// URLs (other origins) never do.
function needsToken(req: HttpRequest<unknown>): boolean {
  const url = req.url;
  return (
    url.startsWith(`${API}/users/`) ||
    url === `${API}/passkeys/registration` ||
    url.startsWith('/auth/line/link/')
  );
}

function withToken(req: HttpRequest<unknown>, token: string | null): HttpRequest<unknown> {
  return token ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }) : req;
}

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  if (!needsToken(req)) {
    return next(req);
  }

  const auth = inject(AuthService);
  const router = inject(Router);

  return next(withToken(req, auth.token())).pipe(
    catchError((err: unknown) => {
      // Only an expired token is worth retrying; a rejected credential in
      // the request body would just be rejected again.
      const expired =
        err instanceof HttpErrorResponse &&
        err.status === 401 &&
        err.error?.error === 'invalid_token';
      if (!expired) {
        return throwError(() => err);
      }

      // The access token expired under us; the session may still be good.
      return from(auth.restore()).pipe(
        switchMap((ok) => {
          if (!ok) {
            void router.navigate(['/login'], { queryParams: { error: 'sign_in_required' } });
            return throwError(() => err);
          }
          return next(withToken(req, auth.token()));
        }),
      );
    }),
  );
};
