import { expect, type Page } from '@playwright/test'

import { test } from './fixtures'

test.describe.configure({ mode: 'parallel' })

/**
 * `disabled` used to be a no-op: declared on `PayloadTOTPConfig` and documented,
 * but never read. Paired with `forceSetup`, which is the reported use case of
 * opting out locally while hosted environments keep enforcing TOTP, every login
 * still landed on the setup page.
 */
test.describe('disabled', () => {
	test.describe.configure({ mode: 'serial' })

	let page: Page
	let teardown: VoidFunction
	let baseURL: string

	test.beforeAll(async ({ setup, browser }) => {
		const setupResult = await setup({ disabled: true, forceSetup: true })
		teardown = setupResult.teardown
		baseURL = setupResult.baseURL
		page = await browser.newPage()
	})

	test.afterAll(async () => {
		await teardown()
		await page.close()
	})

	test('should redirect to dashboard after signup, not to the setup page', async ({
		helpers,
	}) => {
		await helpers.createFirstUser({ page, baseURL })

		await expect(page).toHaveTitle('Dashboard - Payload')
	})

	test('field should be not visible on the account page', async () => {
		await page.goto(`${baseURL}/admin/account`)

		await expect(page.getByText('Authenticator app')).not.toBeVisible()
		await expect(page.locator('css=#totp-ui-field')).not.toBeVisible()
	})

	test('setup view should not be registered', async () => {
		await page.goto(`${baseURL}/admin/setup-totp`)

		await expect(page.getByRole('button', { name: 'Add code manually' })).not.toBeVisible()
	})

	test('verify view should not be registered', async () => {
		await page.goto(`${baseURL}/admin/verify-totp`)

		await expect(page.locator('css=input[type="text"]')).not.toBeVisible()
	})

	test('should stay signed in across a reload', async () => {
		await page.goto(`${baseURL}/admin`)

		await expect(page).toHaveTitle('Dashboard - Payload')
	})
})
