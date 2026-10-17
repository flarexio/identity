import { HttpErrorResponse } from '@angular/common/http';

import { ErrorResponse } from './api';

// Error codes the service answers with (transport/http/errors.go), and the
// ones the LINE callback puts in ?error=.
const messages: Record<string, string> = {
  invalid_credential: '無法驗證此登入憑證，請再試一次。',
  not_registered:
    '這把通行金鑰尚未綁定任何帳號。請先用 Google 或 LINE 登入，再到帳號頁面新增通行金鑰。',
  account_inactive: '此帳號目前已停用。',
  sign_in_required: '登入已逾時，請重新登入。',
  invalid_token: '登入已逾時，請重新登入。',
  already_linked: '這個帳號已經綁定過了。',
  linked_elsewhere: '這個帳號已綁定到另一位使用者。',
  last_account: '至少要保留一種登入方式。',
  passkey_rejected: '通行金鑰驗證失敗。',
  provider_not_supported: '不支援此登入方式。',
  rate_limited: '嘗試次數過多，請稍後再試。',
  cross_site: '請求來源不正確。',
  forbidden: '你沒有權限進行此操作。',
  not_found: '找不到資料。',
  line_failed: 'LINE 登入失敗，請再試一次。',
  line_cancelled: '已取消 LINE 授權。',
};

export function describe(code: string | null | undefined): string {
  return (code && messages[code]) || '發生錯誤，請稍後再試。';
}

export function describeError(err: unknown): string {
  if (err instanceof HttpErrorResponse) {
    const body = err.error as Partial<ErrorResponse> | null;
    if (body && typeof body === 'object' && body.error) {
      return describe(body.error);
    }
    if (err.status === 0) {
      return '無法連線到伺服器。';
    }
  }

  if (err instanceof DOMException && err.name === 'NotAllowedError') {
    return '已取消或逾時。';
  }

  return describe(null);
}
