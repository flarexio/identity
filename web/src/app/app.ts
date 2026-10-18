import { Component, inject } from '@angular/core';
import { Router, RouterLink, RouterOutlet } from '@angular/router';

import { AuthService } from './core/auth';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink],
  template: `
    <header>
      <a class="brand" routerLink="/">Flarex Identity</a>
      @if (auth.user(); as u) {
        <nav>
          <span class="muted who">{{ u.username }}</span>
          <button type="button" class="button small" (click)="signOut()">登出</button>
        </nav>
      }
    </header>
    <main>
      <router-outlet />
    </main>
  `,
  styles: `
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 1rem 1.25rem;
      border-bottom: 1px solid var(--border);
    }

    .brand {
      font-weight: 700;
      color: inherit;
      text-decoration: none;
    }

    nav {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    main {
      width: min(100% - 2rem, 44rem);
      margin-inline: auto;
    }

    @media (max-width: 480px) {
      .who {
        display: none;
      }
    }
  `,
})
export class App {
  protected readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  protected async signOut(): Promise<void> {
    await this.auth.signOut();
    await this.router.navigateByUrl('/login');
  }
}
