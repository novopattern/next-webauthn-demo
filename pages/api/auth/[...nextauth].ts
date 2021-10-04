import { NextApiRequest, NextApiResponse } from 'next';
import NextAuth from 'next-auth';
import EmailProvider from 'next-auth/providers/email';
import { MongoDBAdapter } from '@next-auth/mongodb-adapter';
import { getDb } from '../../../lib/mongodb';
import CredentialsProvider from 'next-auth/providers/credentials';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import base64url from 'base64url';
import { Document } from 'mongodb';
import { DbCredential, getChallenge } from '../../../lib/webauthn';

const domain = process.env.APP_DOMAIN!;
const origin = process.env.APP_ORIGIN!;
const webauthnDbName = process.env.WEBAUTHN_DBNAME!;
const nextAuthDbName = process.env.NEXT_AUTH_DBNAME!;

export default async function auth(req: NextApiRequest, res: NextApiResponse) {
    return NextAuth(req, res, {
        providers: [
            EmailProvider({
                server: process.env.EMAIL_SERVER,
                from: process.env.EMAIL_FROM
            }),
            CredentialsProvider({
                name: 'webauthn',
                credentials: {},
                async authorize(cred, req) {
                    const {
                        id,
                        rawId,
                        type,
                        clientDataJSON,
                        authenticatorData,
                        signature,
                        userHandle,
                    } = req.body;

                    const credential = {
                        id,
                        rawId,
                        type,
                        response: {
                            clientDataJSON,
                            authenticatorData,
                            signature,
                            userHandle,
                        },

                    };
                    const db = await getDb(webauthnDbName);
                    const authenticator = await db.collection<DbCredential & Document>('credentials').findOne({
                        credentialID: credential.id
                    });
                    if (!authenticator) {
                        return null;
                    }
                    const challenge = await getChallenge(authenticator.userID);
                    if (!challenge) {
                        return null;
                    }
                    try {
                        const { verified, authenticationInfo: info } = verifyAuthenticationResponse({
                            credential: credential as any,
                            expectedChallenge: challenge.value,
                            expectedOrigin: origin,
                            expectedRPID: domain,
                            authenticator: {
                                credentialPublicKey: authenticator.credentialPublicKey.buffer as Buffer,
                                credentialID: base64url.toBuffer(authenticator.credentialID),
                                counter: authenticator.counter,
                            },
                        });

                        if (!verified || !info) {
                            return null;
                        }
                        await db.collection<DbCredential>('credentials').updateOne({
                            _id: authenticator._id
                        }, {
                            $set: {
                                counter: info.newCounter
                            }
                        })
                    } catch (err) {
                        console.log(err);
                        return null;
                    }
                    return { email: authenticator.userID };
                }
            })
        ],
        adapter: MongoDBAdapter({
            db: await getDb(nextAuthDbName)
        }),
        session: {
            jwt: true,
        },
        pages: {
            signIn: '/auth/signin',
        }
    })
}