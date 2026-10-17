import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';

import { AuthService } from './auth';

export const signedIn: CanActivateFn = async (route) => {
  const auth = inject(AuthService);
  const router = inject(Router);

  // Coming back from LINE, the account may still be being written.
  const attempts = route.queryParamMap.has('signin') ? 4 : 1;

  if (auth.signedIn() || (await auth.restore(attempts))) {
    return true;
  }

  return router.createUrlTree(['/login']);
};

export const signedOut: CanActivateFn = async () => {
  const auth = inject(AuthService);
  const router = inject(Router);

  if (auth.signedIn() || (await auth.restore())) {
    return router.createUrlTree(['/account']);
  }

  return true;
};
