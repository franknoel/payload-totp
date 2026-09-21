/**
 * Reproduction for TOTP codes being guessable without limit.
 *
 * `/verify-totp` and `/remove-totp` validated the submitted code and answered
 * `ok: false` on a miss, and nothing else. Payload locks an account after
 * `maxLoginAttempts` wrong passwords, but neither endpoint took part in that
 * count, so a caller holding a session could submit six-digit codes until one
 * of the three codes the `window: 1` validation accepts came up.
 *
 * Both endpoints now count each code toward the collection's login lockout,
 * before the code is checked, so a burst of parallel guesses is bounded too.
 */

import type { PayloadRequest } from 'payload'

import { Secret, TOTP } from 'otpauth'

jest.mock('next/headers.js', () => ({
	cookies: async () => ({ delete: jest.fn(), get: jest.fn(), set: jest.fn() }),
}))

import { removeEndpointHandler } from '../src/api/remove'
import { verifyToken } from '../src/api/verifyToken'

const SECRET = 'JBSWY3DPEHPK3PXP'
const USER_ID = 'user-1'
const LOCK_TIME = 600_000

const correctCode = () => new TOTP({ secret: Secret.fromBase32(SECRET) }).generate()
/** Outside the ±1 step window: never equal to a code the validation accepts. */
const WRONG_CODE = '000000'

type UserRow = {
	id: string
	lockUntil?: null | string
	loginAttempts?: null | number
	totpSecret?: null | string
}

/**
 * The one users row the handlers read and write, with the `$inc` that
 * `incrementLoginAttempts` relies on, so the count survives parallel requests.
 */
function buildPayload(maxLoginAttempts: number) {
	const row: UserRow = { id: USER_ID, lockUntil: null, loginAttempts: 0, totpSecret: SECRET }

	const db = {
		findOne: jest.fn(async () => ({ ...row })),
		updateOne: jest.fn(
			async ({ data }: { data: Partial<Record> & { loginAttempts?: any } }) => {
				for (const [key, value] of Object.entries(data)) {
					if (
						key === 'loginAttempts' &&
						value &&
						typeof value === 'object' &&
						'$inc' in value
					) {
						row.loginAttempts = (row.loginAttempts ?? 0) + value.$inc
					} else {
						// eslint-disable-next-line @typescript-eslint/no-explicit-any
						;(row as any)[key] = value
					}
				}

				return { ...row }
			},
		),
	}

	const collection = {
		config: {
			slug: 'users',
			auth: {
				cookies: {},
				lockTime: LOCK_TIME,
				maxLoginAttempts,
				tokenExpiration: 7200,
				useSessions: false,
			},
		},
	}

	const payload = {
		collections: { users: collection },
		config: { cookiePrefix: 'payload' },
		db,
		findByID: jest.fn(async () => ({ totpSecret: row.totpSecret })),
		secret: 'test-secret',
		update: jest.fn(async () => {
			row.totpSecret = null
		}),
	}

	return { payload, row }
}

function buildRequest(payload: unknown, token: unknown): PayloadRequest {
	return {
		i18n: { t: (key: string) => key },
		t: (key: string) => key,
		json: async () => ({ token }),
		payload,
		user: {
			id: USER_ID,
			_strategy: 'local-jwt',
			collection: 'users',
			email: 'user@example.com',
			hasTotp: true,
		},
	} as unknown as PayloadRequest
}

const pluginOptions = { collection: 'users' as const }

describe('verify-totp', () => {
	test('locks the account after maxLoginAttempts wrong codes and refuses the correct one', async () => {
		const { payload, row } = buildPayload(3)
		const handler = verifyToken(pluginOptions)

		for (let i = 0; i < 3; i++) {
			const res = await (await handler(buildRequest(payload, WRONG_CODE))).json()
			expect(res).toEqual({ message: 'totpPlugin:setup:incorrectCode', ok: false })
		}

		expect(row.loginAttempts).toBe(3)
		expect(new Date(row.lockUntil!).getTime()).toBeGreaterThan(Date.now())

		const res = await (await handler(buildRequest(payload, correctCode()))).json()
		expect(res).toEqual({ message: 'error:userLocked', ok: false })
	})

	test('checks no more than maxLoginAttempts codes out of a parallel burst', async () => {
		const { payload } = buildPayload(3)
		const handler = verifyToken(pluginOptions)

		const results = await Promise.all(
			Array.from({ length: 10 }, () =>
				handler(buildRequest(payload, WRONG_CODE)).then((res) => res.json()),
			),
		)

		const checked = results.filter((res) => res.message === 'totpPlugin:setup:incorrectCode')
		const refused = results.filter((res) => res.message === 'error:userLocked')

		expect(checked).toHaveLength(3)
		expect(refused).toHaveLength(7)
	})

	test('resets the count on a correct code', async () => {
		const { payload, row } = buildPayload(3)
		const handler = verifyToken(pluginOptions)

		await handler(buildRequest(payload, WRONG_CODE))
		await handler(buildRequest(payload, WRONG_CODE))
		expect(row.loginAttempts).toBe(2)

		const res = await (await handler(buildRequest(payload, correctCode()))).json()
		expect(res).toEqual({ ok: true })
		expect(row.loginAttempts).toBe(0)
		expect(row.lockUntil).toBeNull()
	})

	test('does not count a malformed body as a guess', async () => {
		const { payload, row } = buildPayload(3)
		const handler = verifyToken(pluginOptions)

		const res = await (await handler(buildRequest(payload, 123456))).json()
		expect(res).toEqual({ message: 'error:unspecific', ok: false })
		expect(row.loginAttempts).toBe(0)
	})

	test('counts nothing when maxLoginAttempts is 0', async () => {
		const { payload, row } = buildPayload(0)
		const handler = verifyToken(pluginOptions)

		for (let i = 0; i < 5; i++) {
			await handler(buildRequest(payload, WRONG_CODE))
		}

		expect(row.loginAttempts).toBe(0)
		expect(payload.db.findOne).not.toHaveBeenCalled()

		const res = await (await handler(buildRequest(payload, correctCode()))).json()
		expect(res).toEqual({ ok: true })
	})
})

describe('remove-totp', () => {
	test('shares the count with verify-totp', async () => {
		const { payload, row } = buildPayload(3)
		const verify = verifyToken(pluginOptions)
		const remove = removeEndpointHandler(pluginOptions)

		await verify(buildRequest(payload, WRONG_CODE))
		await remove(buildRequest(payload, WRONG_CODE))
		await remove(buildRequest(payload, WRONG_CODE))

		expect(row.loginAttempts).toBe(3)

		const res = await (await remove(buildRequest(payload, correctCode()))).json()
		expect(res).toEqual({ message: 'error:userLocked', ok: false })
		expect(row.totpSecret).toBe(SECRET)
	})

	test('resets the count and removes the secret on a correct code', async () => {
		const { payload, row } = buildPayload(3)
		const remove = removeEndpointHandler(pluginOptions)

		await remove(buildRequest(payload, WRONG_CODE))

		const res = await (await remove(buildRequest(payload, correctCode()))).json()
		expect(res).toEqual({ ok: true })
		expect(row.loginAttempts).toBe(0)
		expect(row.totpSecret).toBeNull()
	})
})
