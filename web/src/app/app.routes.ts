import { Routes } from '@angular/router';

import { signedIn, signedOut } from './core/auth.guard';

export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'account' },
  {
    path: 'login',
    title: '登入 · Flarex Identity',
    canActivate: [signedOut],
    loadComponent: () => import('./login/login').then((m) => m.Login),
  },
  {
    path: 'account',
    title: '我的帳號 · Flarex Identity',
    canActivate: [signedIn],
    loadComponent: () => import('./account/account').then((m) => m.Account),
  },
  { path: '**', redirectTo: 'account' },
];
