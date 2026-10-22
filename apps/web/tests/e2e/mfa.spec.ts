import { expect, test } from '@playwright/test'
import { API, signInWithMFA, totpCode } from './helpers'

// Second-factor and passkey flows end to end.
//
// TOTP uses an independent implementation in helpers.ts: agreement between it
// and the server is the assertion. Passkeys use a CDP virtual authenticator,
// so the browser performs a real WebAuthn ceremony against the API.

test.describe('multi-factor authentication', () => {
  test('enrolls TOTP over the API and signs in through the two-step form', async ({ page, request }) => {
    const username = 'mfa-operator'
    const password = 'mfa-operator-password-value'

    // Admin creates the operator.
    let response = await request.post(`${API}/api/v1/auth/login`, {
      data: { username: 'admin', password: 'e2e-dashboard-password' },
    })
    expect(response.ok()).toBeTruthy()
    const adminCsrf = ((await response.json()) as { csrf_token: string }).csrf_token
    response = await request.post(`${API}/api/v1/users`, {
      headers: { 'X-CSRF-Token': adminCsrf },
      data: { username, password, role: 'ANALYST' },
    })
    expect(response.status(), await response.text()).toBe(201)

    // Operator enrolls: setup returns the secret, enable consumes a live code.
    response = await request.post(`${API}/api/v1/auth/login`, { data: { username, password } })
    expect(response.ok()).toBeTruthy()
    const operatorCsrf = ((await response.json()) as { csrf_token: string }).csrf_token
    response = await request.post(`${API}/api/v1/auth/mfa/setup`, {
      headers: { 'X-CSRF-Token': operatorCsrf },
      data: { password },
    })
    expect(response.ok()).toBeTruthy()
    const setup = (await response.json()) as { secret: string }
    expect(setup.secret.length).toBeGreaterThan(16)
    response = await request.post(`${API}/api/v1/auth/mfa/enable`, {
      headers: { 'X-CSRF-Token': operatorCsrf },
      data: { code: totpCode(setup.secret) },
    })
    expect(response.status(), await response.text()).toBe(200)
    const enabled = (await response.json()) as { backup_codes: string[] }
    expect(enabled.backup_codes).toHaveLength(10)

    // The dashboard form prompts for the second factor only after the API
    // answers MFA_REQUIRED, then signs in with a live code.
    await signInWithMFA(page, username, password, () => totpCode(setup.secret))

    // The settings page reports the factor as enabled.
    await page.goto('/settings')
    await expect(page.getByRole('heading', { name: 'Multi-factor authentication' })).toBeVisible()
  })

  test('registers a passkey on a virtual authenticator and signs in passwordless', async ({
    page,
    request,
  }) => {
    // Browsers reject an IP literal as a WebAuthn RP ID, so this flow runs on
    // the localhost origin (the API is spawned with a matching RP config).
    const WEB = 'http://localhost:3100'
    const username = 'pk-operator'
    const password = 'pk-operator-password-value'

    let response = await request.post(`${API}/api/v1/auth/login`, {
      data: { username: 'admin', password: 'e2e-dashboard-password' },
    })
    expect(response.ok()).toBeTruthy()
    const adminCsrf = ((await response.json()) as { csrf_token: string }).csrf_token
    response = await request.post(`${API}/api/v1/users`, {
      headers: { 'X-CSRF-Token': adminCsrf },
      data: { username, password, role: 'ANALYST' },
    })
    expect(response.status(), await response.text()).toBe(201)

    // Password sign-in first: registration requires an authenticated session.
    await page.goto(`${WEB}/login`)
    await page.getByLabel('Username').fill(username)
    await page.getByLabel('Password').fill(password)
    await page.getByRole('button', { name: 'Sign in', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible()

    // A virtual platform authenticator stands in for hardware.
    const cdp = await page.context().newCDPSession(page)
    await cdp.send('WebAuthn.enable')
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    })

    await page.goto(`${WEB}/settings`)
    await expect(page.getByRole('heading', { name: 'Passkeys' })).toBeVisible()
    await page.getByLabel('Passkey name').fill('e2e-key')
    await page.getByLabel('Password for passkey registration').fill(password)
    await page.getByRole('button', { name: 'Register this device' }).click()
    await expect(page.getByText('e2e-key')).toBeVisible()

    // Sign out, then sign back in with the passkey and no password.
    await page.getByRole('button', { name: 'Sign out' }).click()
    await expect(page).toHaveURL(/\/login$/)
    await page.getByLabel('Username').fill(username)
    await page.getByRole('button', { name: 'Sign in with passkey' }).click()
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible()
  })
})
