import { getDb } from './mongodb';
import { Binary } from 'mongodb';

const dbName = process.env.WEBAUTHN_DBNAME!;


export interface DbCredential {
    credentialID: string;
    userID: string;
    transports: AuthenticatorTransport[];
    credentialPublicKey: Binary | Buffer;
    counter: number;
}


export async function saveChallenge({ userID, challenge }: { challenge: string, userID: string }) {
    const db = await getDb(dbName);
    await db.collection('challenge').updateOne({
        userID,
    }, {
        $set: {
            value: challenge
        }
    }, {
        upsert: true
    });
}

export async function getChallenge(userID: string) {
    const db = await getDb(dbName);
    const challengeObj = await db.collection<{ userID: string; value: string; }>('challenge').findOneAndDelete({
        userID
    })
    return challengeObj.value;
}

/**
 * saveCredentials stores the user's public key in the database.
 * @param cred user's public key
 */
export async function saveCredentials(cred: { transports: AuthenticatorTransport[]; credentialID: string; counter: number; userID: string; key: Buffer }) {
    const db = await getDb(dbName);
    await db.collection<DbCredential>('credentials').insertOne({
        credentialID: cred.credentialID,
        transports: cred.transports,
        userID: cred.userID,
        credentialPublicKey: cred.key,
        counter: cred.counter,
    })
}