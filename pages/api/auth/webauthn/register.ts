import { NextApiRequest, NextApiResponse } from 'next';
import { generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server';
import { getSession } from 'next-auth/react';
import { getDb } from '../../../../lib/mongodb';
import { RegistrationCredentialJSON } from '@simplewebauthn/typescript-types';
import { DbCredential, getChallenge, saveChallenge, saveCredentials } from '../../../../lib/webauthn';

const domain = process.env.APP_DOMAIN!;
const origin = process.env.APP_ORIGIN!;
const appName = process.env.APP_NAME!;
const dbName = process.env.WEBAUTHN_DBNAME!;

/**
 * handles GET /api/auth/webauthn/register.
 *
 * This function generates and returns registration options.
 */
async function handlePreRegister(req: NextApiRequest, res: NextApiResponse) {
    const session = await getSession({ req });
    const email = session?.user?.email;
    if (!email) {
        return res.status(401).json({ message: 'Authentication is required' });
    }
    const db = await getDb(dbName);
    const credentials = await db.collection<DbCredential>('credentials').find({
        userID: email,
    }).toArray();

    const options = generateRegistrationOptions({
        rpID: domain,
        rpName: appName,
        userID: email,
        userName: email,
        attestationType: 'none',
        authenticatorSelection: {
            userVerification: 'preferred',
        },
    });
    options.excludeCredentials = credentials.map(c => ({
        id: c.credentialID,
        type: 'public-key',
        transports: c.transports
    }));

    try {
        await saveChallenge({ userID: email, challenge: options.challenge })
    } catch (err) {
        return res.status(500).json({ message: 'Could not set up challenge.' })
    }
    return res.status(200).json(options);
}

/**
 * handles POST /api/auth/webauthn/register.
 *
 * This function verifies and stores user's public key.
 */
async function handleRegister(
    req: NextApiRequest,
    res: NextApiResponse
) {
    const session = await getSession({ req });
    const email = session?.user?.email;
    if (!email) {
        return res.status(401).json({ success: false, message: 'You are not connected.' });
    }
    const challenge = await getChallenge(email);
    if (!challenge) {
        return res.status(401).json({ success: false, message: 'Pre-registration is required.' });
    }
    const credential: RegistrationCredentialJSON = req.body;
    const { verified, registrationInfo: info } = await verifyRegistrationResponse({
        credential,
        expectedRPID: domain,
        expectedOrigin: origin,
        expectedChallenge: challenge.value,
    });
    if (!verified || !info) {
        return res.status(500).json({ success: false, message: 'Something went wrong' });
    }
    try {
        await saveCredentials({
            credentialID: credential.id,
            transports: credential.transports ?? ['internal'],
            userID: email,
            key: info.credentialPublicKey,
            counter: info.counter
        })
        return res.status(201).json({ success: true })
    } catch (err) {
        return res.status(500).json({ success: false, message: 'Could not register the credential.' })
    }
}

export default async function WebauthnRegister(
    req: NextApiRequest,
    res: NextApiResponse
) {
    if (req.method === 'GET') {
        return handlePreRegister(req, res);
    }
    if (req.method === 'POST') {
        return handleRegister(req, res);
    }
    return res.status(404).json({ message: 'The method is forbidden.' })
}