import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { firstValueFrom } from 'rxjs';

import { SignInResponse } from './api';
import { AuthService } from './auth';
import { authInterceptor } from './auth.interceptor';

function response(token: string): SignInResponse {
  return {
    user: {
      id: '01J0000000000000000000000',
      username: 'alice',
      name: 'Alice',
      email: 'alice@example.com',
      status: 'activated',
      accounts: [],
      avatar: '',
      created_at: '2026-01-01T00:00:00Z',
    },
    token: { token, expired_at: new Date(Date.now() + 3_600_000).toISOString() },
  };
}

describe('AuthService and authInterceptor', () => {
  let http: HttpClient;
  let backend: HttpTestingController;
  let auth: AuthService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
      ],
    });

    http = TestBed.inject(HttpClient);
    backend = TestBed.inject(HttpTestingController);
    auth = TestBed.inject(AuthService);
  });

  afterEach(() => {
    auth.clear();
    backend.verify();
  });

  async function signIn(token = 'access-1'): Promise<void> {
    const done = auth.signIn('google', 'id-token');
    const req = backend.expectOne('/identity/v1/signin');
    expect(req.request.method).toBe('PATCH');
    expect(req.request.body).toEqual({ provider: 'google', credential: 'id-token' });
    req.flush(response(token));
    await done;
  }

  it('keeps the token in memory only', async () => {
    await signIn();

    expect(auth.token()).toBe('access-1');
    expect(auth.user()?.username).toBe('alice');
    expect(JSON.stringify({ ...localStorage })).not.toContain('access-1');
    expect(JSON.stringify({ ...sessionStorage })).not.toContain('access-1');
  });

  it('sends the token to identity user routes only', async () => {
    await signIn();

    void firstValueFrom(http.get('/identity/v1/users/alice'));
    expect(backend.expectOne('/identity/v1/users/alice').request.headers.get('Authorization')).toBe(
      'Bearer access-1',
    );

    void firstValueFrom(http.get('/identity/v1/config'));
    expect(backend.expectOne('/identity/v1/config').request.headers.has('Authorization')).toBe(
      false,
    );

    void firstValueFrom(http.get('https://elsewhere.example/identity/v1/users/alice'));
    expect(
      backend
        .expectOne('https://elsewhere.example/identity/v1/users/alice')
        .request.headers.has('Authorization'),
    ).toBe(false);
  });

  it('renews an expired token from the session and retries once', async () => {
    await signIn();

    const result = firstValueFrom(http.get<{ ok: boolean }>('/identity/v1/users/alice'));
    backend
      .expectOne('/identity/v1/users/alice')
      .flush({ error: 'invalid_token', message: '' }, { status: 401, statusText: 'Unauthorized' });

    await Promise.resolve();
    backend.expectOne('/identity/v1/session/token').flush(response('access-2'));

    await new Promise((r) => setTimeout(r));
    const retried = backend.expectOne('/identity/v1/users/alice');
    expect(retried.request.headers.get('Authorization')).toBe('Bearer access-2');
    retried.flush({ ok: true });

    expect(await result).toEqual({ ok: true });
  });

  it('does not retry a rejected credential', async () => {
    await signIn();

    const result = firstValueFrom(http.put('/identity/v1/users/alice/socials', {}));
    backend
      .expectOne('/identity/v1/users/alice/socials')
      .flush(
        { error: 'invalid_credential', message: '' },
        { status: 401, statusText: 'Unauthorized' },
      );

    await expect(result).rejects.toBeTruthy();
    backend.expectNone('/identity/v1/session/token');
  });

  it('reports a missing session as signed out', async () => {
    const restored = auth.restore();
    backend
      .expectOne('/identity/v1/session/token')
      .flush(
        { error: 'sign_in_required', message: '' },
        { status: 401, statusText: 'Unauthorized' },
      );

    expect(await restored).toBe(false);
    expect(auth.signedIn()).toBe(false);
  });
});
