import { NextApiRequest, NextApiResponse } from 'next';
import { generateAuthenticationOptions } from '@simplewebauthn/server'
import { getDb } from '../../../../lib/mongodb';
import { DbCredential, saveChallenge } from '../../../../lib/webauthn';


const dbName = process.env.WEBAUTHN_DBNAME!;

/**
 * handles GET /api/auth/webauthn/authenticate.
 *
 * It generates and returns authentication options.
 */
export default async function WebauthnAuthenticate(
    req: NextApiRequest,
    res: NextApiResponse,
) {
    if (req.method === 'GET') {
        const email = req.query['email'] as string;
        if (!email) {
            return res.status(400).json({ message: 'Email is required.' });
        }
        const db = await getDb(dbName);
        const credentials = await db.collection<DbCredential>('credentials').find({
            userID: email,
        }).toArray();
        const options = generateAuthenticationOptions({
            userVerification: 'preferred',

        });

        options.allowCredentials = credentials.map(c => ({
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
    return res.status(404).json({ message: 'The method is forbidden.' });
}